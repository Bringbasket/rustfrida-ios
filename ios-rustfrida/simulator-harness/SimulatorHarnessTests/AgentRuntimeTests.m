#import <XCTest/XCTest.h>

#import <dlfcn.h>
#import <errno.h>
#import <limits.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>

static const uint8_t RFFrameCommandJSON = 0x02;
static const uint8_t RFFrameHello = 0x80;
static const uint8_t RFFrameLog = 0x81;
static const uint8_t RFFrameEvalOK = 0x83;
static const NSUInteger RFMaximumFrameLength = 4 * 1024 * 1024;

typedef int32_t (*RFAgentEntry)(int32_t fd);

@interface RFFrame : NSObject

@property(nonatomic, assign) uint8_t kind;
@property(nonatomic, copy) NSData *payload;

@end

@implementation RFFrame
@end

static NSError *RFProtocolError(NSString *description) {
    return [NSError errorWithDomain:@"org.rustfrida.SimulatorHarness"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey : description}];
}

static BOOL RFWriteAll(int fd, const void *bytes, size_t length, NSError **error) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            if (error != NULL) {
                *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
            }
            return NO;
        }
        cursor += written;
        length -= (size_t)written;
    }
    return YES;
}

static BOOL RFReadAll(int fd, void *bytes, size_t length, NSError **error) {
    uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t count = read(fd, cursor, length);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            if (error != NULL) {
                NSString *description = count == 0 ? @"agent transport closed unexpectedly" : @"agent transport read failed";
                *error = count == 0 ? RFProtocolError(description)
                                    : [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
            }
            return NO;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return YES;
}

static BOOL RFSendJSONCommand(int fd, id command, NSError **error) {
    NSData *payload = [NSJSONSerialization dataWithJSONObject:command options:NSJSONWritingFragmentsAllowed error:error];
    if (payload == nil || payload.length > UINT32_MAX) {
        return NO;
    }

    uint32_t length = (uint32_t)payload.length;
    uint8_t header[5] = {
        RFFrameCommandJSON,
        (uint8_t)(length & 0xff),
        (uint8_t)((length >> 8) & 0xff),
        (uint8_t)((length >> 16) & 0xff),
        (uint8_t)((length >> 24) & 0xff),
    };
    return RFWriteAll(fd, header, sizeof(header), error) &&
           RFWriteAll(fd, payload.bytes, payload.length, error);
}

static RFFrame *RFReadFrame(int fd, NSError **error) {
    uint8_t header[5];
    if (!RFReadAll(fd, header, sizeof(header), error)) {
        return nil;
    }

    uint32_t length = (uint32_t)header[1] |
                      ((uint32_t)header[2] << 8) |
                      ((uint32_t)header[3] << 16) |
                      ((uint32_t)header[4] << 24);
    if (length > RFMaximumFrameLength) {
        if (error != NULL) {
            *error = RFProtocolError([NSString stringWithFormat:@"agent frame is too large: %u", length]);
        }
        return nil;
    }

    NSMutableData *payload = [NSMutableData dataWithLength:length];
    if (length > 0 && !RFReadAll(fd, payload.mutableBytes, length, error)) {
        return nil;
    }

    RFFrame *frame = [[RFFrame alloc] init];
    frame.kind = header[0];
    frame.payload = payload;
    return frame;
}

static NSString *RFFrameText(RFFrame *frame) {
    return [[NSString alloc] initWithData:frame.payload encoding:NSUTF8StringEncoding];
}

static BOOL RFConfigureSocket(int fd, NSError **error) {
    int noSigPipe = 1;
    struct timeval timeout = {.tv_sec = 30, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0) {
        return YES;
    }
    if (error != NULL) {
        *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
    }
    return NO;
}

@interface AgentRuntimeTests : XCTestCase
@end

@implementation AgentRuntimeTests

- (void)testAgentDylibProtocolRoundTrip {
    NSString *dylibPath = [NSBundle.mainBundle.privateFrameworksPath stringByAppendingPathComponent:@"libagent.dylib"];
    XCTAssertTrue([NSFileManager.defaultManager fileExistsAtPath:dylibPath], @"missing embedded agent at %@", dylibPath);

    void *handle = dlopen(dylibPath.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    XCTAssertNotEqual(handle, NULL, @"dlopen failed: %s", dlerror());
    if (handle == NULL) {
        return;
    }

    RFAgentEntry entry = (RFAgentEntry)dlsym(handle, "ios_agent_entry");
    XCTAssertNotEqual(entry, NULL, @"dlsym failed: %s", dlerror());
    if (entry == NULL) {
        dlclose(handle);
        return;
    }

    int sockets[2] = {-1, -1};
    XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0, @"socketpair failed: %s", strerror(errno));
    if (sockets[0] < 0 || sockets[1] < 0) {
        dlclose(handle);
        return;
    }
    NSError *socketError = nil;
    if (!RFConfigureSocket(sockets[0], &socketError) || !RFConfigureSocket(sockets[1], &socketError)) {
        XCTFail(@"socket configuration failed: %@", socketError);
        close(sockets[0]);
        close(sockets[1]);
        dlclose(handle);
        return;
    }

    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    __block int32_t entryResult = INT32_MIN;
    __block BOOL entryFinished = NO;
    int agentSocket = sockets[1];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        entryResult = entry(agentSocket);
        dispatch_semaphore_signal(finished);
    });

    @try {
        NSError *error = nil;
        RFFrame *frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"HELLO read failed: %@", error);
            return;
        }
        NSString *hello = RFFrameText(frame);
        XCTAssertEqual(frame.kind, RFFrameHello);
        XCTAssertNotNil(hello);
        XCTAssertTrue([hello containsString:@"platform=ios"]);
#if defined(__arm64__)
        XCTAssertTrue([hello containsString:@"arch=aarch64"]);
#elif defined(__x86_64__)
        XCTAssertTrue([hello containsString:@"arch=x86_64"]);
#endif
        XCTAssertTrue([hello containsString:@"runtime=quickjs-runtime"]);
        XCTAssertTrue([hello containsString:@"transport=unix-fd"]);

        error = nil;
        if (!RFSendJSONCommand(sockets[0], @{@"kind" : @"ping"}, &error)) {
            XCTFail(@"Ping write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Ping read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        XCTAssertEqualObjects(RFFrameText(frame), @"pong");

        error = nil;
        if (!RFSendJSONCommand(sockets[0], @{@"kind" : @"js_init"}, &error)) {
            XCTFail(@"JsInit write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"JsInit read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        XCTAssertGreaterThan(frame.payload.length, 0U);

        NSDictionary *loadJS = @{
            @"kind" : @"load_js",
            @"script" : @"rpc.exports = { add(a, b) { return a + b; }, structured() { return { object: { flag: true }, array: [1, { x: 'y' }] }; } }; 6 * 7"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], loadJS, &error)) {
            XCTFail(@"LoadJs write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"LoadJs read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        XCTAssertEqualObjects(RFFrameText(frame), @"42");

        NSDictionary *rpcCall = @{
            @"kind" : @"rpc_call",
            @"method" : @"add",
            @"args_json" : @"[19,23]"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], rpcCall, &error)) {
            XCTFail(@"RpcCall write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"RpcCall read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        XCTAssertEqualObjects(RFFrameText(frame), @"42");

        NSDictionary *structuredRPC = @{
            @"kind" : @"rpc_call",
            @"method" : @"structured",
            @"args_json" : @"[]"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], structuredRPC, &error)) {
            XCTFail(@"Structured RpcCall write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Structured RpcCall read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        NSError *jsonError = nil;
        id structuredResult = [NSJSONSerialization JSONObjectWithData:frame.payload options:0 error:&jsonError];
        XCTAssertNil(jsonError);
        XCTAssertEqualObjects(
            structuredResult,
            (@{@"object" : @{@"flag" : @YES}, @"array" : @[@1, @{@"x" : @"y"}]})
        );

        NSDictionary *compoundEval = @{
            @"kind" : @"js_eval",
            @"script" : @"({ object: { flag: true }, array: [1, { x: 'y' }] })"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], compoundEval, &error)) {
            XCTFail(@"Compound JsEval write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Compound JsEval read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        jsonError = nil;
        id compoundResult = [NSJSONSerialization JSONObjectWithData:frame.payload options:0 error:&jsonError];
        XCTAssertNil(jsonError);
        XCTAssertEqualObjects(compoundResult, structuredResult);

        NSDictionary *stalkerLifecycleEval = @{
            @"kind" : @"js_eval",
            @"script" : @"(function() { const t = 8801; Stalker.follow(t, {events:12, queueCapacity:8}); const pausedState = Stalker.pauseThread(t); const paused = Stalker.recordBlock(t, [0x20,0x00,0x80,0xd2,0xc0,0x03,0x5f,0xd6], 0x4000, [{address:0x4000},{address:0x4004}], {events:12, maxEvents:8}); const activeState = Stalker.resumeThread(t); const active = Stalker.recordBlock(t, [0x20,0x00,0x80,0xd2,0xc0,0x03,0x5f,0xd6], 0x4000, [{address:0x4000},{address:0x4004}], {events:12, maxEvents:8}); const events = Stalker.flush(t); const stopped = Stalker.unfollow(t); const collected = Stalker.garbageCollect(t); return {paused:pausedState.state, pausedAccepted:paused.acceptedEvents, pausedNotQueued:paused.notQueuedEvents, resumed:activeState.state, resumedAccepted:active.acceptedEvents, eventCount:events.length, unfollowed:stopped.state, collected:collected, instrumented:active.instrumented}; })()"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], stalkerLifecycleEval, &error)) {
            XCTFail(@"Stalker lifecycle JsEval write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Stalker lifecycle JsEval read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        jsonError = nil;
        id stalkerLifecycleResult = [NSJSONSerialization JSONObjectWithData:frame.payload options:0 error:&jsonError];
        XCTAssertNil(jsonError);
        XCTAssertEqualObjects(
            stalkerLifecycleResult,
            (@{
                @"paused" : @"deactivated",
                @"pausedAccepted" : @0,
                @"pausedNotQueued" : @3,
                @"resumed" : @"following",
                @"resumedAccepted" : @3,
                @"eventCount" : @3,
                @"unfollowed" : @"idle",
                @"collected" : @YES,
                @"instrumented" : @NO,
            })
        );

        NSDictionary *stalkerRelocationEval = @{
            @"kind" : @"js_eval",
            @"script" : @"(function() { const bytes = [0x02,0x00,0x00,0x14]; const cacheBytes = [0x02,0x00,0x00,0x14,0xc0,0x03,0x5f,0xd6]; const near = Stalker.relocate(bytes, 0x10000000, 0x10008000); const far = Stalker.relocate(bytes, 0x1000, 0x100000000); const layout = Stalker.layoutCodeCache(cacheBytes, 0x1000, 0x100000000); const emission = Stalker.emitCodeCache(cacheBytes, 0x1000, 0x100000000); return {available:Stalker.capabilities().directRelocationPlan, layoutAvailable:Stalker.capabilities().staticCodeCacheLayout, emissionAvailable:Stalker.capabilities().staticCodeCacheEmission, nearComplete:near.directlyRelocatable, nearStatus:near.instructions[0].status, nearTarget:near.instructions[0].target, nearOutput:near.output.length, farComplete:far.directlyRelocatable, farFallback:far.requiresFallback, farStatus:far.instructions[0].status, farOutput:far.output, layoutMode:layout.codeCacheLayoutMode, layoutMaterialized:layout.materialized, layoutExecutable:layout.executable, layoutBlockCount:layout.blockCount, layoutFirstBlockStatus:layout.blocks[0].status, layoutFallbackCount:layout.fallbackCount, layoutFallbackStrategy:layout.fallbacks[0].strategy, layoutIslandBytes:layout.islandByteCount, layoutTotalBytes:layout.totalByteCount, layoutOutput:layout.output, emissionMode:emission.mode, emissionComplete:emission.emissionComplete, emissionExecutionReady:emission.executionReady, emissionScratchPolicy:emission.scratchRegisterPolicy, emissionMaterialized:emission.materialized, emissionExecutable:emission.executable, emissionFallbackBytes:emission.fallbackEmittedByteCounts[0], emissionOutputBytes:emission.outputByteCount, emissionPatchedBytes:emission.output.slice(0, 4)}; })()"
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], stalkerRelocationEval, &error)) {
            XCTFail(@"Stalker relocation JsEval write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Stalker relocation JsEval read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
        jsonError = nil;
        id stalkerRelocationResult = [NSJSONSerialization JSONObjectWithData:frame.payload options:0 error:&jsonError];
        XCTAssertNil(jsonError);
        XCTAssertEqualObjects(
            stalkerRelocationResult,
            (@{
                @"available" : @YES,
                @"layoutAvailable" : @YES,
                @"emissionAvailable" : @YES,
                @"nearComplete" : @YES,
                @"nearStatus" : @"relocated",
                @"nearTarget" : @268435464,
                @"nearOutput" : @4,
                @"farComplete" : @NO,
                @"farFallback" : @YES,
                @"farStatus" : @"out-of-range",
                @"farOutput" : [NSNull null],
                @"layoutMode" : @"static-only",
                @"layoutMaterialized" : @NO,
                @"layoutExecutable" : @NO,
                @"layoutBlockCount" : @2,
                @"layoutFirstBlockStatus" : @"fallback-reserved",
                @"layoutFallbackCount" : @1,
                @"layoutFallbackStrategy" : @"branch-island",
                @"layoutIslandBytes" : @64,
                @"layoutTotalBytes" : @80,
                @"layoutOutput" : [NSNull null],
                @"emissionMode" : @"static-emission",
                @"emissionComplete" : @YES,
                @"emissionExecutionReady" : @NO,
                @"emissionScratchPolicy" : @"aapcs64-ip0-veneer",
                @"emissionMaterialized" : @NO,
                @"emissionExecutable" : @NO,
                @"emissionFallbackBytes" : @8,
                @"emissionOutputBytes" : @80,
                @"emissionPatchedBytes" : (@[@4, @0, @0, @20]),
            })
        );

        NSString *cmoduleScript;
#if defined(__arm64__)
        cmoduleScript = @"const m = new CModule('int answer(void) { return 42; }'); new NativeFunction(m.answer, 'int', [])()";
#else
        cmoduleScript = @"const m = new CModule('int answer(void) { return 42; }'); CModule.available && String(m.findSymbolByName('answer')) === String(m.answer)";
#endif
        NSDictionary *cmoduleEval = @{
            @"kind" : @"js_eval",
            @"script" : cmoduleScript
        };
        error = nil;
        if (!RFSendJSONCommand(sockets[0], cmoduleEval, &error)) {
            XCTFail(@"CModule JsEval write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"CModule JsEval read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameEvalOK);
#if defined(__arm64__)
        XCTAssertEqualObjects(RFFrameText(frame), @"42");
#else
        XCTAssertEqualObjects(RFFrameText(frame), @"true");
#endif

        error = nil;
        if (!RFSendJSONCommand(sockets[0], @{@"kind" : @"exit"}, &error)) {
            XCTFail(@"Exit write failed: %@", error);
            return;
        }
        frame = RFReadFrame(sockets[0], &error);
        if (frame == nil) {
            XCTFail(@"Exit read failed: %@", error);
            return;
        }
        XCTAssertEqual(frame.kind, RFFrameLog);
        XCTAssertEqualObjects(RFFrameText(frame), @"bye");

        long waitResult = dispatch_semaphore_wait(finished, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
        entryFinished = waitResult == 0;
        XCTAssertEqual(waitResult, 0L, @"ios_agent_entry did not return after Exit");
        XCTAssertEqual(entryResult, 0);
    } @finally {
        close(sockets[0]);
        if (!entryFinished) {
            entryFinished = dispatch_semaphore_wait(finished, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)) == 0;
        }
        if (entryFinished) {
            dlclose(handle);
        } else {
            XCTFail(@"ios_agent_entry did not stop after its transport closed");
        }
    }
}

@end
