#include <stddef.h>
#include <stdint.h>

typedef struct objc_selector *SEL;
typedef struct objc_class *Class;
typedef struct objc_method *Method;
typedef struct objc_ivar *Ivar;
typedef struct objc_property *objc_property_t;

struct objc_super {
    id receiver;
    Class super_class;
};

extern id objc_msgSend(id receiver, SEL selector, ...);
extern id objc_msgSendSuper(struct objc_super *super_info, SEL selector, ...);
extern id objc_retain(id object);
extern id objc_autorelease(id object);
extern void objc_release(id object);
extern id objc_storeWeak(id *location, id object);
extern id objc_loadWeakRetained(id *location);
extern void objc_destroyWeak(id *location);
extern id objc_getProperty(id object, SEL selector, ptrdiff_t offset, _Bool atomic);
extern void objc_setProperty(id object, SEL selector, ptrdiff_t offset, id value, _Bool atomic,
                             signed char should_copy);
extern void objc_copyStruct(void *destination, const void *source, ptrdiff_t size, _Bool atomic,
                            _Bool has_strong);
extern Class objc_getClass(const char *name);
extern SEL sel_registerName(const char *name);
extern const char *sel_getName(SEL selector);
extern Class object_getClass(id object);
extern Class class_getSuperclass(Class cls);
extern _Bool class_addMethod(Class cls, SEL name, const void *implementation, const char *types);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern Method *class_copyMethodList(Class cls, unsigned int *count);
extern SEL method_getName(Method method);
extern const void *method_getImplementation(Method method);
extern const char *method_getTypeEncoding(Method method);
extern objc_property_t *class_copyPropertyList(Class cls, unsigned int *count);
extern const char *property_getName(objc_property_t property);
extern char *property_copyAttributeValue(objc_property_t property, const char *attribute_name);
extern Ivar class_getInstanceVariable(Class cls, const char *name);
extern ptrdiff_t ivar_getOffset(Ivar ivar);
extern void *malloc(size_t size);
extern void free(void *pointer);

static const char *RF_MANAGED_PROPERTY_MARKER = "__iosRustFrida_managedPropertyLifecycle";

#define RF_MANUAL_KVO_MARKER_PREFIX "__iosRustFrida_manualKVO_"
#define RF_MANUAL_KVO_MAX_PROPERTY_BYTES 255
#define RF_MANUAL_KVO_MARKER_CAPACITY                                                                     \
    (sizeof(RF_MANUAL_KVO_MARKER_PREFIX) + (RF_MANUAL_KVO_MAX_PROPERTY_BYTES * 2))

static const char *RF_AUTOMATIC_KVO_SELECTOR = "automaticallyNotifiesObserversForKey:";

#if defined(__OBJC_BOOL_IS_BOOL) && __OBJC_BOOL_IS_BOOL
typedef _Bool RfObjcBool;
#else
typedef signed char RfObjcBool;
#endif

typedef struct RfManagedDeallocFrame {
    id object;
    Class next_class;
    struct RfManagedDeallocFrame *previous;
} RfManagedDeallocFrame;

static _Thread_local RfManagedDeallocFrame *rf_managed_dealloc_frames;

typedef struct RfManualKvoFrame {
    Class receiver;
    Class next_metaclass;
    struct RfManualKvoFrame *previous;
} RfManualKvoFrame;

static _Thread_local RfManualKvoFrame *rf_manual_kvo_frames;

typedef struct RfManualKvoChangeFrame {
    struct RfManualKvoChangeFrame *previous;
    id object;
    id key;
    size_t property_length;
    char property_name[];
} RfManualKvoChangeFrame;

static _Thread_local RfManualKvoChangeFrame *rf_manual_kvo_change_frames;

typedef struct {
    Class string_class;
    SEL alloc_selector;
    SEL init_selector;
    SEL will_selector;
    SEL did_selector;
} RfManualKvoCapabilities;

void rf_objc_managed_property_marker(id object, SEL selector);
void rf_objc_managed_property_dealloc(id object, SEL selector);
static void rf_objc_manual_kvo_marker(id object, SEL selector);
static RfObjcBool rf_objc_manual_kvo_automatically_notifies(Class receiver, SEL selector, id key);

enum {
    RF_OBJC_VOID = 0,
    RF_OBJC_BOOL = 1,
    RF_OBJC_I8 = 2,
    RF_OBJC_U8 = 3,
    RF_OBJC_I16 = 4,
    RF_OBJC_U16 = 5,
    RF_OBJC_I32 = 6,
    RF_OBJC_U32 = 7,
    RF_OBJC_I64 = 8,
    RF_OBJC_U64 = 9,
    RF_OBJC_ISIZE = 10,
    RF_OBJC_USIZE = 11,
    RF_OBJC_POINTER = 12,
};

typedef struct {
    char name[128];
    char reason[512];
} RfObjcExceptionInfo;

static void rf_copy_bytes(char *destination, size_t capacity, const char *source) {
    size_t index = 0;
    if (capacity == 0) {
        return;
    }
    if (source != NULL) {
        while (index + 1 < capacity && source[index] != '\0') {
            destination[index] = source[index];
            index++;
        }
    }
    destination[index] = '\0';
}

static const char *rf_exception_string(id exception, const char *selector_name) {
    SEL value_selector = sel_registerName(selector_name);
    SEL utf8_selector = sel_registerName("UTF8String");
    id (*send_object)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
    const char *(*send_utf8)(id, SEL) = (const char *(*)(id, SEL))objc_msgSend;
    id value = send_object(exception, value_selector);
    return value == (id)0 ? NULL : send_utf8(value, utf8_selector);
}

static void rf_capture_exception(id exception, RfObjcExceptionInfo *info) {
    if (info == NULL) {
        return;
    }
    info->name[0] = '\0';
    info->reason[0] = '\0';
    @try {
        rf_copy_bytes(info->name, sizeof(info->name), rf_exception_string(exception, "name"));
    } @catch (id ignored) {
        (void)ignored;
    }
    @try {
        rf_copy_bytes(info->reason, sizeof(info->reason), rf_exception_string(exception, "reason"));
    } @catch (id ignored) {
        (void)ignored;
    }
}

static Method rf_class_declared_method(Class cls, SEL selector) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = (Method)0;
    for (unsigned int index = 0; index < count; index++) {
        if (method_getName(methods[index]) == selector) {
            found = methods[index];
            break;
        }
    }
    free(methods);
    return found;
}

static _Bool rf_class_declares_selector(Class cls, SEL selector) {
    return rf_class_declared_method(cls, selector) != (Method)0;
}

static _Bool rf_bytes_equal(const char *left, const char *right, size_t length) {
    if (left == NULL || right == NULL) {
        return 0;
    }
    for (size_t index = 0; index < length; index++) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

static _Bool rf_string_equals_length(const char *candidate, const char *expected, size_t expected_length) {
    if (candidate == NULL || expected == NULL) {
        return 0;
    }
    for (size_t index = 0; index < expected_length; index++) {
        if (candidate[index] == '\0' || candidate[index] != expected[index]) {
            return 0;
        }
    }
    return candidate[expected_length] == '\0';
}

static _Bool rf_strings_equal(const char *left, const char *right) {
    if (left == NULL || right == NULL) {
        return 0;
    }
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) {
            return 0;
        }
        index++;
    }
    return left[index] == right[index];
}

static objc_property_t rf_class_declared_property_named(Class cls, const char *property_name,
                                                        size_t property_length) {
    unsigned int count = 0;
    objc_property_t *properties = class_copyPropertyList(cls, &count);
    objc_property_t found = (objc_property_t)0;
    for (unsigned int index = 0; index < count; index++) {
        const char *candidate = property_getName(properties[index]);
        if (rf_string_equals_length(candidate, property_name, property_length)) {
            found = properties[index];
            break;
        }
    }
    free(properties);
    return found;
}

static Class rf_find_property_declaring_class(Class cls, const char *property_name, size_t property_length) {
    for (Class current = cls; current != (Class)0; current = class_getSuperclass(current)) {
        if (rf_class_declared_property_named(current, property_name, property_length) != (objc_property_t)0) {
            return current;
        }
    }
    return (Class)0;
}

static Method rf_class_declared_method_named(Class cls, const char *method_name) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = (Method)0;
    for (unsigned int index = 0; index < count; index++) {
        const char *candidate = sel_getName(method_getName(methods[index]));
        if (rf_strings_equal(candidate, method_name)) {
            found = methods[index];
            break;
        }
    }
    free(methods);
    return found;
}

static _Bool rf_encoding_character_is_one_of(char value, const char *accepted) {
    for (size_t index = 0; accepted[index] != '\0'; index++) {
        if (value == accepted[index]) {
            return 1;
        }
    }
    return 0;
}

static void rf_skip_encoding_qualifiers(const char **cursor) {
    while (rf_encoding_character_is_one_of(**cursor, "rnNoORV")) {
        (*cursor)++;
    }
}

static void rf_skip_encoding_offset(const char **cursor) {
    if (**cursor == '+' || **cursor == '-') {
        (*cursor)++;
    }
    while (**cursor >= '0' && **cursor <= '9') {
        (*cursor)++;
    }
}

static _Bool rf_consume_encoded_type(const char **cursor, const char *accepted) {
    rf_skip_encoding_qualifiers(cursor);
    if (!rf_encoding_character_is_one_of(**cursor, accepted)) {
        return 0;
    }
    char type = **cursor;
    (*cursor)++;
    if (type == '@' && **cursor == '"') {
        (*cursor)++;
        while (**cursor != '\0' && **cursor != '"') {
            (*cursor)++;
        }
        if (**cursor != '"') {
            return 0;
        }
        (*cursor)++;
    }
    rf_skip_encoding_offset(cursor);
    return 1;
}

static _Bool rf_method_is_manual_kvo_marker(Method method) {
    if (method == (Method)0 || method_getImplementation(method) != (const void *)rf_objc_manual_kvo_marker) {
        return 0;
    }
    const char *cursor = method_getTypeEncoding(method);
    return cursor != NULL && rf_consume_encoded_type(&cursor, "v") && rf_consume_encoded_type(&cursor, "@") &&
           rf_consume_encoded_type(&cursor, ":") && *cursor == '\0';
}

static _Bool rf_method_has_compatible_automatic_kvo_signature(Method method) {
    if (method == (Method)0) {
        return 0;
    }
    const char *cursor = method_getTypeEncoding(method);
    return cursor != NULL && rf_consume_encoded_type(&cursor, "BcC") && rf_consume_encoded_type(&cursor, "@") &&
           rf_consume_encoded_type(&cursor, ":") && rf_consume_encoded_type(&cursor, "@") && *cursor == '\0';
}

static _Bool rf_method_is_manual_kvo_override(Method method) {
    return rf_method_has_compatible_automatic_kvo_signature(method) &&
           method_getImplementation(method) == (const void *)rf_objc_manual_kvo_automatically_notifies;
}

static _Bool rf_manual_kvo_property_length(const char *property_name, size_t *length) {
    if (property_name == NULL || length == NULL) {
        return 0;
    }
    size_t index = 0;
    while (index <= RF_MANUAL_KVO_MAX_PROPERTY_BYTES && property_name[index] != '\0') {
        if ((unsigned char)property_name[index] > 0x7f) {
            return 0;
        }
        index++;
    }
    if (index == 0 || index > RF_MANUAL_KVO_MAX_PROPERTY_BYTES) {
        return 0;
    }
    *length = index;
    return 1;
}

static _Bool rf_manual_kvo_marker_name(const char *property_name,
                                       char marker[RF_MANUAL_KVO_MARKER_CAPACITY]) {
    size_t property_length = 0;
    if (!rf_manual_kvo_property_length(property_name, &property_length)) {
        return 0;
    }

    size_t marker_length = 0;
    while (RF_MANUAL_KVO_MARKER_PREFIX[marker_length] != '\0') {
        marker[marker_length] = RF_MANUAL_KVO_MARKER_PREFIX[marker_length];
        marker_length++;
    }

    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < property_length; index++) {
        unsigned char byte = (unsigned char)property_name[index];
        marker[marker_length++] = digits[byte >> 4];
        marker[marker_length++] = digits[byte & 0x0f];
    }
    marker[marker_length] = '\0';
    return 1;
}

static Class rf_find_manual_kvo_override_metaclass(Class receiver) {
    Class start = object_getClass((id)receiver);
    for (RfManualKvoFrame *frame = rf_manual_kvo_frames; frame != NULL; frame = frame->previous) {
        if (frame->receiver == receiver) {
            start = frame->next_metaclass;
            break;
        }
    }

    SEL selector = sel_registerName(RF_AUTOMATIC_KVO_SELECTOR);
    for (Class metaclass = start; metaclass != (Class)0; metaclass = class_getSuperclass(metaclass)) {
        Method method = rf_class_declared_method(metaclass, selector);
        if (rf_method_is_manual_kvo_override(method)) {
            return metaclass;
        }
    }
    return (Class)0;
}

static _Bool rf_manual_kvo_capabilities(Class object_class, RfManualKvoCapabilities *capabilities) {
    if (object_class == (Class)0 || capabilities == NULL) {
        return 0;
    }
    Class string_class = objc_getClass("NSString");
    Class string_metaclass = string_class == (Class)0 ? (Class)0 : object_getClass((id)string_class);
    SEL alloc_selector = sel_registerName("alloc");
    SEL init_selector = sel_registerName("initWithUTF8String:");
    SEL will_selector = sel_registerName("willChangeValueForKey:");
    SEL did_selector = sel_registerName("didChangeValueForKey:");
    if (string_metaclass == (Class)0 || alloc_selector == NULL || init_selector == NULL || will_selector == NULL ||
        did_selector == NULL || class_getInstanceMethod(string_metaclass, alloc_selector) == (Method)0 ||
        class_getInstanceMethod(string_class, init_selector) == (Method)0 ||
        class_getInstanceMethod(object_class, will_selector) == (Method)0 ||
        class_getInstanceMethod(object_class, did_selector) == (Method)0) {
        return 0;
    }

    capabilities->string_class = string_class;
    capabilities->alloc_selector = alloc_selector;
    capabilities->init_selector = init_selector;
    capabilities->will_selector = will_selector;
    capabilities->did_selector = did_selector;
    return 1;
}

/*
 * Stable status contract for installers and exception-catching helpers:
 * 0 = success, 1 = Objective-C exception or runtime-definition conflict,
 * 2 = invalid input, overlong property name, or missing runtime capability.
 */
int rf_objc_install_manual_kvo(Class cls, const char *property_name) {
    char marker_name[RF_MANUAL_KVO_MARKER_CAPACITY];
    size_t property_length = 0;
    if (cls == (Class)0 || !rf_manual_kvo_property_length(property_name, &property_length) ||
        !rf_manual_kvo_marker_name(property_name, marker_name)) {
        return 2;
    }
    if (rf_class_declared_property_named(cls, property_name, property_length) == (objc_property_t)0) {
        return 2;
    }

    Class metaclass = object_getClass((id)cls);
    SEL automatic_selector = sel_registerName(RF_AUTOMATIC_KVO_SELECTOR);
    if (metaclass == (Class)0 || automatic_selector == NULL) {
        return 2;
    }

    Method marker = rf_class_declared_method_named(cls, marker_name);
    if (marker != (Method)0 && !rf_method_is_manual_kvo_marker(marker)) {
        return 1;
    }

    Method direct_override = rf_class_declared_method(metaclass, automatic_selector);
    if (direct_override != (Method)0 && !rf_method_is_manual_kvo_override(direct_override)) {
        return 1;
    }

    Class super_metaclass = class_getSuperclass(metaclass);
    Method inherited_override = super_metaclass == (Class)0
                                    ? (Method)0
                                    : class_getInstanceMethod(super_metaclass, automatic_selector);
    if (inherited_override == (Method)0 || !rf_method_has_compatible_automatic_kvo_signature(inherited_override)) {
        return 2;
    }

    const char *inherited_types = method_getTypeEncoding(inherited_override);
    if (inherited_types == NULL) {
        return 2;
    }
    RfManualKvoCapabilities capabilities;
    if (!rf_manual_kvo_capabilities(cls, &capabilities)) {
        return 2;
    }
    _Bool install_override = direct_override == (Method)0 &&
                             !rf_method_is_manual_kvo_override(inherited_override);

    SEL marker_selector = sel_registerName(marker_name);
    if (marker_selector == NULL) {
        return 2;
    }

    if (install_override) {
        Method current_effective = class_getInstanceMethod(metaclass, automatic_selector);
        if (!rf_method_is_manual_kvo_override(current_effective) &&
            !class_addMethod(metaclass, automatic_selector,
                             (const void *)rf_objc_manual_kvo_automatically_notifies, inherited_types)) {
            direct_override = rf_class_declared_method(metaclass, automatic_selector);
            if (!rf_method_is_manual_kvo_override(direct_override)) {
                return 1;
            }
        }
    }

    if (marker == (Method)0 &&
        !class_addMethod(cls, marker_selector, (const void *)rf_objc_manual_kvo_marker, "v@:")) {
        marker = rf_class_declared_method(cls, marker_selector);
        if (!rf_method_is_manual_kvo_marker(marker)) {
            return 1;
        }
    }
    return 0;
}

int32_t rf_objc_property_uses_manual_kvo(Class cls, const char *property_name) {
    char marker_name[RF_MANUAL_KVO_MARKER_CAPACITY];
    size_t property_length = 0;
    if (cls == (Class)0 || !rf_manual_kvo_property_length(property_name, &property_length) ||
        !rf_manual_kvo_marker_name(property_name, marker_name)) {
        return 0;
    }

    Class declaring_class = rf_find_property_declaring_class(cls, property_name, property_length);
    if (declaring_class == (Class)0) {
        return 0;
    }
    Method marker = rf_class_declared_method_named(declaring_class, marker_name);
    return rf_method_is_manual_kvo_marker(marker) ? 1 : 0;
}

static void rf_objc_manual_kvo_marker(id object, SEL selector) {
    (void)object;
    (void)selector;
}

static RfObjcBool rf_objc_manual_kvo_automatically_notifies(Class receiver, SEL selector, id key) {
    if (receiver == (Class)0) {
        return 1;
    }
    if (key != (id)0) {
        SEL utf8_selector = sel_registerName("UTF8String");
        const char *(*send_utf8)(id, SEL) = (const char *(*)(id, SEL))objc_msgSend;
        const char *property_name = send_utf8(key, utf8_selector);
        if (property_name != NULL && rf_objc_property_uses_manual_kvo(receiver, property_name)) {
            return 0;
        }
    }

    Class declaring_metaclass = rf_find_manual_kvo_override_metaclass(receiver);
    Class super_metaclass = declaring_metaclass == (Class)0
                                ? (Class)0
                                : class_getSuperclass(declaring_metaclass);
    if (super_metaclass == (Class)0) {
        return 1;
    }

    RfManualKvoFrame frame = {receiver, super_metaclass, rf_manual_kvo_frames};
    struct objc_super super_info = {(id)receiver, super_metaclass};
    RfObjcBool result = 1;
    rf_manual_kvo_frames = &frame;
    @try {
        result = ((RfObjcBool(*)(struct objc_super *, SEL, id))objc_msgSendSuper)(&super_info, selector, key);
    } @finally {
        rf_manual_kvo_frames = frame.previous;
    }
    return result;
}

static Class rf_find_managed_property_class(Class start) {
    SEL marker = sel_registerName(RF_MANAGED_PROPERTY_MARKER);
    for (Class cls = start; cls != (Class)0; cls = class_getSuperclass(cls)) {
        if (rf_class_declares_selector(cls, marker)) {
            return cls;
        }
    }
    return (Class)0;
}

static _Bool rf_property_has_attribute(objc_property_t property, const char *name) {
    char *value = property_copyAttributeValue(property, name);
    if (value == NULL) {
        return 0;
    }
    free(value);
    return 1;
}

static void rf_destroy_managed_properties(id object, Class declaring_class) {
    unsigned int count = 0;
    objc_property_t *properties = class_copyPropertyList(declaring_class, &count);
    for (unsigned int index = 0; index < count; index++) {
        objc_property_t property = properties[index];
        char *backing_name = property_copyAttributeValue(property, "V");
        if (backing_name == NULL) {
            continue;
        }
        _Bool is_weak = rf_property_has_attribute(property, "W");
        _Bool is_owned = rf_property_has_attribute(property, "&") || rf_property_has_attribute(property, "C");
        Ivar ivar = (is_weak || is_owned) ? class_getInstanceVariable(declaring_class, backing_name) : (Ivar)0;
        free(backing_name);
        if (ivar == (Ivar)0) {
            continue;
        }

        id *location = (id *)((uint8_t *)object + ivar_getOffset(ivar));
        @try {
            if (is_weak) {
                objc_destroyWeak(location);
            } else {
                id previous = *location;
                *location = (id)0;
                if (previous != (id)0) {
                    objc_release(previous);
                }
            }
        } @catch (id ignored) {
            (void)ignored;
        }
    }
    free(properties);
}

int rf_objc_install_managed_property_lifecycle(Class cls) {
    if (cls == (Class)0) {
        return 3;
    }
    SEL marker = sel_registerName(RF_MANAGED_PROPERTY_MARKER);
    SEL dealloc = sel_registerName("dealloc");
    if (rf_class_declares_selector(cls, marker)) {
        return 1;
    }
    if (rf_class_declares_selector(cls, dealloc)) {
        return 2;
    }
    if (!class_addMethod(cls, marker, (const void *)rf_objc_managed_property_marker, "v@:")) {
        return 1;
    }
    if (!class_addMethod(cls, dealloc, (const void *)rf_objc_managed_property_dealloc, "v@:")) {
        return 2;
    }
    return 0;
}

void rf_objc_managed_property_marker(id object, SEL selector) {
    (void)object;
    (void)selector;
}

void rf_objc_managed_property_dealloc(id object, SEL selector) {
    if (object == (id)0) {
        return;
    }

    Class start = object_getClass(object);
    for (RfManagedDeallocFrame *frame = rf_managed_dealloc_frames; frame != NULL; frame = frame->previous) {
        if (frame->object == object) {
            start = frame->next_class;
            break;
        }
    }
    Class declaring_class = rf_find_managed_property_class(start);
    if (declaring_class == (Class)0) {
        return;
    }

    rf_destroy_managed_properties(object, declaring_class);
    Class superclass = class_getSuperclass(declaring_class);
    if (superclass == (Class)0) {
        return;
    }

    RfManagedDeallocFrame frame = {object, superclass, rf_managed_dealloc_frames};
    struct objc_super super_info = {object, superclass};
    rf_managed_dealloc_frames = &frame;
    @try {
        ((void (*)(struct objc_super *, SEL))objc_msgSendSuper)(&super_info, selector);
    } @finally {
        rf_managed_dealloc_frames = frame.previous;
    }
}

#define RF_INVOKE(return_type)                                                                                         \
    ({                                                                                                                 \
        return_type rf_value;                                                                                          \
        switch (argument_count) {                                                                                      \
        case 0:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL))objc_msgSend)(receiver, selector);                                    \
            break;                                                                                                     \
        case 1:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL, uintptr_t))objc_msgSend)(receiver, selector, arguments[0]);           \
            break;                                                                                                     \
        case 2:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL, uintptr_t, uintptr_t))objc_msgSend)(                                  \
                receiver, selector, arguments[0], arguments[1]);                                                       \
            break;                                                                                                     \
        case 3:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(                       \
                receiver, selector, arguments[0], arguments[1], arguments[2]);                                         \
            break;                                                                                                     \
        case 4:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(            \
                receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3]);                           \
            break;                                                                                                     \
        case 5:                                                                                                        \
            rf_value = ((return_type(*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)( \
                receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);            \
            break;                                                                                                     \
        default:                                                                                                       \
            rf_value =                                                                                                 \
                ((return_type(*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))           \
                     objc_msgSend)(receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3],         \
                                   arguments[4], arguments[5]);                                                        \
            break;                                                                                                     \
        }                                                                                                              \
        rf_value;                                                                                                      \
    })

#define RF_STORE(return_type)                                                                                          \
    do {                                                                                                               \
        return_type value = RF_INVOKE(return_type);                                                                    \
        *result = (uintptr_t)value;                                                                                    \
    } while (0)

#define RF_INVOKE_VOID()                                                                                               \
    do {                                                                                                               \
        switch (argument_count) {                                                                                      \
        case 0:                                                                                                        \
            ((void (*)(id, SEL))objc_msgSend)(receiver, selector);                                                     \
            break;                                                                                                     \
        case 1:                                                                                                        \
            ((void (*)(id, SEL, uintptr_t))objc_msgSend)(receiver, selector, arguments[0]);                            \
            break;                                                                                                     \
        case 2:                                                                                                        \
            ((void (*)(id, SEL, uintptr_t, uintptr_t))objc_msgSend)(receiver, selector, arguments[0], arguments[1]);   \
            break;                                                                                                     \
        case 3:                                                                                                        \
            ((void (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(                                        \
                receiver, selector, arguments[0], arguments[1], arguments[2]);                                         \
            break;                                                                                                     \
        case 4:                                                                                                        \
            ((void (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(                             \
                receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3]);                           \
            break;                                                                                                     \
        case 5:                                                                                                        \
            ((void (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(                  \
                receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);            \
            break;                                                                                                     \
        default:                                                                                                       \
            ((void (*)(id, SEL, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))objc_msgSend)(       \
                receiver, selector, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],             \
                arguments[5]);                                                                                         \
            break;                                                                                                     \
        }                                                                                                              \
    } while (0)

int rf_objc_try_msg_send(id receiver, SEL selector, const uintptr_t *arguments, size_t argument_count,
                         uint32_t return_kind, uintptr_t *result, RfObjcExceptionInfo *exception_info) {
    if (receiver == (id)0 || selector == NULL || result == NULL || argument_count > 6 ||
        (argument_count != 0 && arguments == NULL)) {
        return 2;
    }
    *result = 0;
    @try {
        switch (return_kind) {
        case RF_OBJC_VOID:
            RF_INVOKE_VOID();
            break;
        case RF_OBJC_BOOL:
            RF_STORE(_Bool);
            break;
        case RF_OBJC_I8:
            RF_STORE(int8_t);
            break;
        case RF_OBJC_U8:
            RF_STORE(uint8_t);
            break;
        case RF_OBJC_I16:
            RF_STORE(int16_t);
            break;
        case RF_OBJC_U16:
            RF_STORE(uint16_t);
            break;
        case RF_OBJC_I32:
            RF_STORE(int32_t);
            break;
        case RF_OBJC_U32:
            RF_STORE(uint32_t);
            break;
        case RF_OBJC_I64:
            RF_STORE(int64_t);
            break;
        case RF_OBJC_U64:
            RF_STORE(uint64_t);
            break;
        case RF_OBJC_ISIZE:
            RF_STORE(intptr_t);
            break;
        case RF_OBJC_USIZE:
        case RF_OBJC_POINTER:
            RF_STORE(uintptr_t);
            break;
        default:
            return 2;
        }
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_retain(id object, id *result, RfObjcExceptionInfo *exception_info) {
    if (object == (id)0 || result == NULL) {
        return 2;
    }
    @try {
        *result = objc_retain(object);
        return 0;
    } @catch (id exception) {
        *result = (id)0;
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_copy(id object, id *result, RfObjcExceptionInfo *exception_info) {
    if (object == (id)0 || result == NULL) {
        return 2;
    }
    @try {
        SEL selector = sel_registerName("copyWithZone:");
        id (*send_copy)(id, SEL, void *) = (id (*)(id, SEL, void *))objc_msgSend;
        *result = send_copy(object, selector, NULL);
        return *result == (id)0 ? 2 : 0;
    } @catch (id exception) {
        *result = (id)0;
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_atomic_get_object(id object, SEL selector, ptrdiff_t offset, id *result,
                                  RfObjcExceptionInfo *exception_info) {
    if (object == (id)0 || selector == NULL || result == NULL) {
        return 2;
    }
    *result = (id)0;
    @try {
        *result = objc_getProperty(object, selector, offset, 1);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_atomic_set_object(id object, SEL selector, ptrdiff_t offset, id value, _Bool should_copy,
                                  RfObjcExceptionInfo *exception_info) {
    if (object == (id)0 || selector == NULL) {
        return 2;
    }
    @try {
        objc_setProperty(object, selector, offset, value, 1, should_copy ? 1 : 0);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

static _Bool rf_objc_atomic_value_size_is_supported(size_t size) {
    return size == 1 || size == 2 || size == 4 || size == 8;
}

int rf_objc_try_atomic_load_value(const void *location, void *result, size_t size,
                                  RfObjcExceptionInfo *exception_info) {
    if (location == NULL || result == NULL || !rf_objc_atomic_value_size_is_supported(size)) {
        return 2;
    }
    @try {
        objc_copyStruct(result, location, (ptrdiff_t)size, 1, 0);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_atomic_store_value(void *location, const void *value, size_t size,
                                   RfObjcExceptionInfo *exception_info) {
    if (location == NULL || value == NULL || !rf_objc_atomic_value_size_is_supported(size)) {
        return 2;
    }
    @try {
        objc_copyStruct(location, value, (ptrdiff_t)size, 1, 0);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

static void rf_objc_kvo_release(id object, int *status, RfObjcExceptionInfo *exception_info) {
    if (object == (id)0) {
        return;
    }
    @try {
        objc_release(object);
    } @catch (id exception) {
        if (*status != 1) {
            rf_capture_exception(exception, exception_info);
        }
        *status = 1;
    }
}

int rf_objc_try_kvo_will_change(id object, const char *property_name,
                                RfObjcExceptionInfo *exception_info) {
    size_t property_length = 0;
    if (object == (id)0 || !rf_manual_kvo_property_length(property_name, &property_length)) {
        return 2;
    }

    Class object_class = object_getClass(object);
    RfManualKvoCapabilities capabilities;
    if (!rf_manual_kvo_capabilities(object_class, &capabilities)) {
        return 2;
    }

    size_t allocation_size = sizeof(RfManualKvoChangeFrame) + property_length + 1;
    RfManualKvoChangeFrame *frame = (RfManualKvoChangeFrame *)malloc(allocation_size);
    if (frame == NULL) {
        return 2;
    }
    frame->previous = NULL;
    frame->object = (id)0;
    frame->key = (id)0;
    frame->property_length = property_length;
    for (size_t index = 0; index <= property_length; index++) {
        frame->property_name[index] = property_name[index];
    }

    id allocated_string = (id)0;
    id key = (id)0;
    id retained_object = (id)0;
    int status = 2;
    @try {
        allocated_string = ((id(*)(id, SEL))objc_msgSend)((id)capabilities.string_class,
                                                          capabilities.alloc_selector);
        if (allocated_string != (id)0) {
            key = ((id(*)(id, SEL, const char *))objc_msgSend)(allocated_string, capabilities.init_selector,
                                                              property_name);
            allocated_string = (id)0;
        }
        if (key != (id)0) {
            retained_object = objc_retain(object);
        }
        if (retained_object != (id)0) {
            ((void (*)(id, SEL, id))objc_msgSend)(object, capabilities.will_selector, key);
            frame->previous = rf_manual_kvo_change_frames;
            frame->object = retained_object;
            frame->key = key;
            rf_manual_kvo_change_frames = frame;
            retained_object = (id)0;
            key = (id)0;
            frame = NULL;
            status = 0;
        }
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        status = 1;
    }

    rf_objc_kvo_release(key, &status, exception_info);
    rf_objc_kvo_release(allocated_string, &status, exception_info);
    rf_objc_kvo_release(retained_object, &status, exception_info);
    free(frame);
    return status;
}

int rf_objc_try_kvo_did_change(id object, const char *property_name,
                               RfObjcExceptionInfo *exception_info) {
    size_t property_length = 0;
    if (object == (id)0 || !rf_manual_kvo_property_length(property_name, &property_length)) {
        return 2;
    }

    RfManualKvoChangeFrame *frame = rf_manual_kvo_change_frames;
    if (frame == NULL || frame->object != object || frame->property_length != property_length ||
        !rf_bytes_equal(frame->property_name, property_name, property_length)) {
        return 2;
    }
    rf_manual_kvo_change_frames = frame->previous;

    int status = 2;
    Class object_class = object_getClass(object);
    SEL did_selector = sel_registerName("didChangeValueForKey:");
    if (object_class != (Class)0 && did_selector != NULL &&
        class_getInstanceMethod(object_class, did_selector) != (Method)0) {
        @try {
            ((void (*)(id, SEL, id))objc_msgSend)(object, did_selector, frame->key);
            status = 0;
        } @catch (id exception) {
            rf_capture_exception(exception, exception_info);
            status = 1;
        }
    }

    rf_objc_kvo_release(frame->key, &status, exception_info);
    rf_objc_kvo_release(frame->object, &status, exception_info);
    free(frame);
    return status;
}

int rf_objc_try_release(id object, RfObjcExceptionInfo *exception_info) {
    if (object == (id)0) {
        return 2;
    }
    @try {
        objc_release(object);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_store_weak(id *location, id object, RfObjcExceptionInfo *exception_info) {
    if (location == NULL) {
        return 2;
    }
    @try {
        objc_storeWeak(location, object);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_load_weak(id *location, id *result, RfObjcExceptionInfo *exception_info) {
    if (location == NULL || result == NULL) {
        return 2;
    }
    *result = (id)0;
    @try {
        id loaded = objc_loadWeakRetained(location);
        *result = loaded == (id)0 ? (id)0 : objc_autorelease(loaded);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}

int rf_objc_try_destroy_weak(id *location, RfObjcExceptionInfo *exception_info) {
    if (location == NULL) {
        return 2;
    }
    @try {
        objc_destroyWeak(location);
        return 0;
    } @catch (id exception) {
        rf_capture_exception(exception, exception_info);
        return 1;
    }
}
