// Bounded Objective-C heap enumeration used by ObjC.chooseSync/choose.
// The declarations are local so the non-Apple cross-build does not need SDK
// headers while Apple builds still resolve the system APIs at link time.

#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#define RF_HAS_PTRAUTH 1
#endif
#endif

#ifndef RF_HAS_PTRAUTH
#define RF_HAS_PTRAUTH 0
#endif

typedef void *Class;
typedef uint32_t mach_port_t;
typedef mach_port_t task_t;
typedef uintptr_t vm_address_t;
typedef uintptr_t vm_size_t;
typedef int kern_return_t;

enum {
    RF_KERN_SUCCESS = 0,
    RF_MALLOC_PTR_IN_USE_RANGE_TYPE = 1,
};

typedef struct {
    vm_address_t address;
    vm_size_t size;
} RfVmRange;

typedef kern_return_t (*RfMemoryReader)(task_t task, vm_address_t address, vm_size_t size, void **local_memory);
typedef void (*RfVmRangeRecorder)(task_t task, void *user_data, unsigned type, RfVmRange *ranges, unsigned count);
typedef kern_return_t (*RfMallocEnumerator)(
    task_t task,
    void *user_data,
    unsigned type_mask,
    vm_address_t zone_address,
    RfMemoryReader reader,
    RfVmRangeRecorder recorder);

typedef struct {
    RfMallocEnumerator enumerator;
} RfMallocIntrospection;

// malloc_zone_t has the introspection pointer after twelve pointer-sized
// fields on the supported Apple ABIs. The rest of the private structure is
// intentionally omitted because the scanner only needs introspect.
typedef struct {
    void *reserved[12];
    RfMallocIntrospection *introspect;
} RfMallocZonePrefix;

typedef struct {
    uintptr_t *keys;
    size_t *sizes;
    size_t mask;
} RfClassTable;

typedef struct {
    RfClassTable classes;
    uintptr_t *matches;
    size_t match_count;
    size_t match_capacity;
} RfChooseContext;

extern Class objc_getClass(const char *name);
extern int objc_getClassList(Class *buffer, int buffer_count);
extern Class class_getSuperclass(Class cls);
extern size_t class_getInstanceSize(Class cls);
extern kern_return_t malloc_get_all_zones(
    task_t task,
    RfMemoryReader reader,
    vm_address_t **addresses,
    unsigned *count);
extern mach_port_t mach_task_self_;
extern void *malloc(size_t size);
extern void free(void *pointer);

static size_t rf_next_power_of_two(size_t value) {
    size_t result = 1;
    while (result < value && result <= (SIZE_MAX / 2)) {
        result <<= 1;
    }
    return result;
}

static size_t rf_hash_pointer(uintptr_t value) {
    value ^= value >> 33;
    value *= (uintptr_t)0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= (uintptr_t)0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return (size_t)value;
}

static int rf_class_table_init(RfClassTable *table, size_t class_count) {
    if (class_count > (SIZE_MAX / 2) - 1) {
        return 0;
    }
    size_t requested = class_count * 2 + 1;
    size_t capacity = rf_next_power_of_two(requested < 16 ? 16 : requested);
    if (capacity == 0 || capacity > (SIZE_MAX / sizeof(uintptr_t)) || capacity > (SIZE_MAX / sizeof(size_t))) {
        return 0;
    }
    table->keys = (uintptr_t *)malloc(capacity * sizeof(uintptr_t));
    table->sizes = (size_t *)malloc(capacity * sizeof(size_t));
    if (table->keys == NULL || table->sizes == NULL) {
        free(table->keys);
        free(table->sizes);
        table->keys = NULL;
        table->sizes = NULL;
        return 0;
    }
    for (size_t i = 0; i != capacity; i++) {
        table->keys[i] = 0;
        table->sizes[i] = 0;
    }
    table->mask = capacity - 1;
    return 1;
}

static void rf_class_table_destroy(RfClassTable *table) {
    free(table->keys);
    free(table->sizes);
    table->keys = NULL;
    table->sizes = NULL;
    table->mask = 0;
}

static void rf_class_table_insert(RfClassTable *table, Class cls, size_t instance_size) {
    uintptr_t key = (uintptr_t)cls;
    if (key == 0 || instance_size == 0 || table->keys == NULL) {
        return;
    }
    size_t index = rf_hash_pointer(key) & table->mask;
    for (;;) {
        if (table->keys[index] == 0 || table->keys[index] == key) {
            table->keys[index] = key;
            table->sizes[index] = instance_size;
            return;
        }
        index = (index + 1) & table->mask;
    }
}

static size_t rf_class_table_lookup(const RfClassTable *table, uintptr_t key) {
    if (key == 0 || table->keys == NULL) {
        return 0;
    }
    size_t index = rf_hash_pointer(key) & table->mask;
    for (;;) {
        uintptr_t candidate = table->keys[index];
        if (candidate == 0) {
            return 0;
        }
        if (candidate == key) {
            return table->sizes[index];
        }
        index = (index + 1) & table->mask;
    }
}

static int rf_is_subclass_of(Class candidate, Class target) {
    Class current = candidate;
    while (current != NULL) {
        if (current == target) {
            return 1;
        }
        current = class_getSuperclass(current);
    }
    return 0;
}

static uintptr_t rf_normalize_isa(uintptr_t isa) {
#if defined(__aarch64__) || defined(__arm64__)
    return isa & (uintptr_t)0xffffffff8ULL;
#elif defined(__x86_64__)
    return isa & (uintptr_t)0x7ffffffffff8ULL;
#else
    return isa & ~(uintptr_t)0x7;
#endif
}

static RfMallocIntrospection *rf_strip_introspection(RfMallocIntrospection *introspect) {
#if RF_HAS_PTRAUTH
    return (RfMallocIntrospection *)ptrauth_strip(introspect, ptrauth_key_asda);
#else
    return introspect;
#endif
}

static RfMallocEnumerator rf_prepare_enumerator(RfMallocEnumerator enumerator) {
#if RF_HAS_PTRAUTH
    return (RfMallocEnumerator)ptrauth_sign_unauthenticated(
        ptrauth_strip(enumerator, ptrauth_key_asia),
        ptrauth_key_asia,
        0);
#else
    return enumerator;
#endif
}

static int rf_match_already_recorded(const RfChooseContext *context, uintptr_t object) {
    for (size_t i = 0; i != context->match_count; i++) {
        if (context->matches[i] == object) {
            return 1;
        }
    }
    return 0;
}

static void rf_collect_matches(
    task_t task,
    void *user_data,
    unsigned type,
    RfVmRange *ranges,
    unsigned count) {
    (void)task;
    if (type != RF_MALLOC_PTR_IN_USE_RANGE_TYPE || user_data == NULL || ranges == NULL) {
        return;
    }
    RfChooseContext *context = (RfChooseContext *)user_data;
    for (unsigned i = 0; i != count && context->match_count < context->match_capacity; i++) {
        const RfVmRange *range = &ranges[i];
        if (range->address == 0 || range->size < sizeof(uintptr_t)) {
            continue;
        }
        uintptr_t isa = *(const uintptr_t *)(uintptr_t)range->address;
        size_t instance_size = rf_class_table_lookup(&context->classes, rf_normalize_isa(isa));
        if (instance_size == 0 || range->size < instance_size) {
            continue;
        }
        uintptr_t object = (uintptr_t)range->address;
        if (!rf_match_already_recorded(context, object)) {
            context->matches[context->match_count++] = object;
        }
    }
}

static kern_return_t rf_read_local_memory(
    task_t task,
    vm_address_t address,
    vm_size_t size,
    void **local_memory) {
    (void)task;
    (void)size;
    if (local_memory == NULL) {
        return 1;
    }
    *local_memory = (void *)(uintptr_t)address;
    return RF_KERN_SUCCESS;
}

int rf_objc_choose_instances(
    const char *class_name,
    int include_subclasses,
    size_t max_count,
    uintptr_t *matches,
    size_t *match_count) {
    if (class_name == NULL || matches == NULL || match_count == NULL || max_count == 0) {
        return 2;
    }
    *match_count = 0;

    Class target = objc_getClass(class_name);
    if (target == NULL) {
        return 0;
    }

    int class_buffer_count = objc_getClassList(NULL, 0);
    if (class_buffer_count < 0) {
        return 3;
    }
    size_t class_count = (size_t)class_buffer_count;
    Class *class_buffer = NULL;
    if (class_count != 0) {
        if (class_count > SIZE_MAX / sizeof(Class)) {
            return 3;
        }
        class_buffer = (Class *)malloc(class_count * sizeof(Class));
        if (class_buffer == NULL) {
            return 3;
        }
        int actual_count = objc_getClassList(class_buffer, class_buffer_count);
        if (actual_count < 0) {
            free(class_buffer);
            return 3;
        }
        class_count = (size_t)actual_count < class_count ? (size_t)actual_count : class_count;
    }

    RfChooseContext context;
    context.matches = matches;
    context.match_count = 0;
    context.match_capacity = max_count;
    if (!rf_class_table_init(&context.classes, class_count)) {
        free(class_buffer);
        return 3;
    }

    if (include_subclasses) {
        for (size_t i = 0; i != class_count; i++) {
            Class candidate = class_buffer[i];
            if (candidate != NULL && rf_is_subclass_of(candidate, target)) {
                rf_class_table_insert(&context.classes, candidate, class_getInstanceSize(candidate));
            }
        }
    } else {
        rf_class_table_insert(&context.classes, target, class_getInstanceSize(target));
    }

    vm_address_t *zone_addresses = NULL;
    unsigned zone_count = 0;
    kern_return_t zones_status = malloc_get_all_zones(
        mach_task_self_,
        rf_read_local_memory,
        &zone_addresses,
        &zone_count);
    if (zones_status == RF_KERN_SUCCESS && zone_addresses != NULL) {
        for (unsigned i = 0; i != zone_count && context.match_count < context.match_capacity; i++) {
            vm_address_t zone_address = zone_addresses[i];
            if (zone_address == 0) {
                continue;
            }
            RfMallocZonePrefix *zone = (RfMallocZonePrefix *)(uintptr_t)zone_address;
            RfMallocIntrospection *introspect = rf_strip_introspection(zone->introspect);
            if (introspect == NULL || introspect->enumerator == NULL) {
                continue;
            }
            RfMallocEnumerator enumerator = rf_prepare_enumerator(introspect->enumerator);
            if (enumerator == NULL) {
                continue;
            }
            enumerator(
                mach_task_self_,
                &context,
                RF_MALLOC_PTR_IN_USE_RANGE_TYPE,
                zone_address,
                rf_read_local_memory,
                rf_collect_matches);
        }
    }

    *match_count = context.match_count;
    rf_class_table_destroy(&context.classes);
    free(class_buffer);
    return zones_status == RF_KERN_SUCCESS ? 0 : 4;
}
