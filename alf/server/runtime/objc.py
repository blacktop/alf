"""
Runtime ObjC interrogation via LLDB expression evaluation.

These helpers are inspired by Hilda's in-process snippets but kept lightweight.
"""

from __future__ import annotations

from ..lldb import LLDBDirector


def runtime_objc_classes(director: LLDBDirector, max_results: int = 200) -> str:
    """Dump ObjC class names from the running process."""
    # TODO(phase2): Pre-compile/inject this helper (e.g., as a dylib command) to avoid
    # recompiling a large ObjC expression blob on every call.
    expr = f"""
    (void)({{
        unsigned int count = 0;
        Class *classes = (Class *)objc_copyClassList(&count);
        unsigned int lim = count;
        if (lim > {max_results}) lim = {max_results};
        for (unsigned int i = 0; i < lim; i++) {{
            const char *name = class_getName(classes[i]);
            if (name) printf("%s\\n", name);
        }}
        free(classes);
    }})
    """
    cmd = "expression -l objc -O -- " + " ".join(expr.split())
    return director.execute_lldb_command(cmd)


FROM_NS_TO_JSON_SNIPPET = r"""
@import Foundation;

__block NSObject *(^make_json_serializable)(NSObject *, BOOL isKey);
// TODO(phase2): Consider injecting this as a persistent helper to avoid JIT cost per call.

NSArray *(^make_json_serializable_array)(NSArray *) = ^(NSArray *src) {
    NSMutableArray *result = [NSMutableArray new];
    [src enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL * stop) {
        [result addObject:make_json_serializable(obj, NO)];
    }];
    return result;
};

NSDictionary *(^make_json_serializable_dictionary)(NSDictionary *) = ^(NSDictionary *src) {
    NSMutableDictionary *result = [NSMutableDictionary new];
    [src enumerateKeysAndObjectsUsingBlock:^(id key, id  obj, BOOL * stop) {
        result[(NSString *)make_json_serializable(key, YES)] = make_json_serializable(obj, NO);
    }];
    return result;
};

make_json_serializable = ^(NSObject *obj, BOOL isKey) {
    if ([obj isKindOfClass:[NSSet class]]) {
        obj = [(NSSet *)obj allObjects];
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        obj = (NSObject *)(make_json_serializable_dictionary((NSDictionary *)obj));
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        obj = (NSObject *)(make_json_serializable_array((NSArray *)obj));
    }
    if ([obj isKindOfClass:[NSData class]]) {
        obj = (NSObject *)[NSString
            stringWithFormat:@"__alf_magic_key__|NSData|%@", [(NSData *)obj base64EncodedStringWithOptions:0]
        ];
    }
    if ([obj isKindOfClass:[NSDate class]]) {
        obj = (NSObject *)[NSString
            stringWithFormat:@"__alf_magic_key__|NSDate|%@",
            [NSNumber numberWithDouble: [(NSDate *)obj timeIntervalSince1970]]
        ];
    }
    if (!isKey || [obj isKindOfClass:[NSString class]]) {
        return obj;
    }
    if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
        NSString *jsonDump = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        NSString *type = [obj isKindOfClass:[NSDictionary class]] ? @"NSDictionary" : @"NSArray";
        return (NSObject *) [NSString
            stringWithFormat:@"__alf_magic_key__|%@|%@", type, jsonDump
        ];
    }
    if ([obj isKindOfClass:[NSNumber class]]) {
        return (NSObject *) [NSString
            stringWithFormat:@"__alf_magic_key__|NSNumber|%@", [(NSNumber *)obj stringValue]
        ];
    }
    if ([obj isKindOfClass:[NSNull class]]) {
        return (NSObject *) [NSString stringWithFormat:@"__alf_magic_key__|NSNull|"];
    }
    return obj;
};
NSDictionary *wrapper = @{@"root": (NSObject *)__ns_object_address__};
wrapper = make_json_serializable_dictionary(wrapper);
NSData *jsonData = [NSJSONSerialization dataWithJSONObject:wrapper options:0 error:nil];
[[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
"""


def runtime_nsobject_to_json(director: LLDBDirector, address_or_expr: str) -> str:
    """Serialize an NSObject in the target process into a JSON string."""
    addr_val = director.evaluate_address(address_or_expr)
    addr_expr = f"0x{addr_val:x}" if addr_val is not None else address_or_expr
    expr = FROM_NS_TO_JSON_SNIPPET.replace("__ns_object_address__", addr_expr)
    cmd = "expression -l objc -O -- " + " ".join(expr.split())
    return director.execute_lldb_command(cmd)


OBJC_CLASS_DUMP_SNIPPET = r"""
@import ObjectiveC;
@import Foundation;

unsigned int outCount = 0;
unsigned int i = 0, j = 0;

uintptr_t (^strip_pac)(uintptr_t) = ^(uintptr_t x) {
    return x & 0x0000ffffffffffff;
};

Class objcClass = (Class)__class_address__;
if (!objcClass) {
    objcClass = objc_getClass("__class_name__");
}

if (!objcClass) {
    @"error: objc class not found";
} else {
    NSDictionary *classDescription = @{
        @"protocols": [NSMutableArray new],
        @"ivars": [NSMutableArray new],
        @"properties": [NSMutableArray new],
        @"methods": [NSMutableArray new],
        @"name": [NSString stringWithCString:class_getName(objcClass) encoding:NSUTF8StringEncoding],
        @"address": [NSNumber numberWithLong:(uintptr_t)objcClass],
        @"super": [NSNumber numberWithLong:(uintptr_t)class_getSuperclass(objcClass)],
    };

    id *protocolList = class_copyProtocolList(objcClass, &outCount);
    for (i = 0; i < outCount; ++i) {
        [classDescription[@"protocols"] addObject:
            [NSString stringWithCString:protocol_getName(protocolList[i]) encoding:NSUTF8StringEncoding]];
    }
    if (protocolList) {
        free(protocolList);
    }

    Ivar *ivars = class_copyIvarList(objcClass, &outCount);
    for (i = 0; i < outCount; ++i) {
        [classDescription[@"ivars"] addObject:@{
            @"name": [NSString stringWithCString:ivar_getName(ivars[i]) encoding:NSUTF8StringEncoding],
            @"type": [NSString stringWithCString:ivar_getTypeEncoding(ivars[i]) encoding:NSUTF8StringEncoding],
            @"offset": [NSNumber numberWithInt:ivar_getOffset(ivars[i])],
        }];
    }
    if (ivars) {
        free(ivars);
    }

    NSMutableArray *fetchedProperties = [NSMutableArray new];
    NSString *propertyName;
    objc_property_t *properties = class_copyPropertyList(objcClass, &outCount);
    for (i = 0; i < outCount; ++i) {
        propertyName = [NSString stringWithCString:property_getName(properties[i])
                                          encoding:NSUTF8StringEncoding];
        if ([fetchedProperties containsObject:propertyName]) {
            continue;
        } else {
            [fetchedProperties addObject:propertyName];
        }
        [classDescription[@"properties"] addObject:@{
            @"name": propertyName,
            @"attributes": [NSString stringWithCString:property_getAttributes(properties[i])
                                              encoding:NSUTF8StringEncoding],
        }];
    }
    if (properties) {
        free(properties);
    }

    Method *methods = class_copyMethodList(object_getClass(objcClass), &outCount);
    unsigned int argsCount;
    NSMutableArray *argsTypes;
    char *methodArgumentsTypes;
    char *methodReturnType;
    for (i = 0; i < outCount; ++i) {
        argsCount = method_getNumberOfArguments(methods[i]);
        argsTypes = [NSMutableArray new];
        for (j = 0; j < argsCount; ++j) {
            methodArgumentsTypes = method_copyArgumentType(methods[i], j);
            [argsTypes addObject:[NSString stringWithCString:methodArgumentsTypes
                                                   encoding:NSUTF8StringEncoding]];
            if (methodArgumentsTypes) {
                free(methodArgumentsTypes);
            }
        }
        methodReturnType = method_copyReturnType(methods[i]);
        [classDescription[@"methods"] addObject:@{
            @"name": [NSString stringWithCString:sel_getName(method_getName(methods[i]))
                                        encoding:NSUTF8StringEncoding],
            @"address": [NSNumber numberWithLong:strip_pac((uintptr_t)(methods[i]))],
            @"imp": [NSNumber numberWithLong:strip_pac(method_getImplementation(methods[i]))],
            @"is_class": @YES,
            @"type": [NSString stringWithCString:method_getTypeEncoding(methods[i])
                                        encoding:NSUTF8StringEncoding],
            @"return_type": [NSString stringWithCString:methodReturnType
                                              encoding:NSUTF8StringEncoding],
            @"args_types": argsTypes,
        }];
        if (methodReturnType) {
            free(methodReturnType);
        }
    }
    if (methods) {
        free(methods);
    }

    methods = class_copyMethodList(objcClass, &outCount);
    for (i = 0; i < outCount; ++i) {
        argsCount = method_getNumberOfArguments(methods[i]);
        argsTypes = [NSMutableArray new];
        for (j = 0; j < argsCount; ++j) {
            methodArgumentsTypes = method_copyArgumentType(methods[i], j);
            [argsTypes addObject:[NSString stringWithCString:methodArgumentsTypes
                                                   encoding:NSUTF8StringEncoding]];
            if (methodArgumentsTypes) {
                free(methodArgumentsTypes);
            }
        }
        methodReturnType = method_copyReturnType(methods[i]);
        [classDescription[@"methods"] addObject:@{
            @"name": [NSString stringWithCString:sel_getName(method_getName(methods[i]))
                                        encoding:NSUTF8StringEncoding],
            @"address": [NSNumber numberWithLong:strip_pac((uintptr_t)(methods[i]))],
            @"imp": [NSNumber numberWithLong:strip_pac(method_getImplementation(methods[i]))],
            @"is_class": @NO,
            @"type": [NSString stringWithCString:method_getTypeEncoding(methods[i])
                                        encoding:NSUTF8StringEncoding],
            @"return_type": [NSString stringWithCString:methodReturnType
                                              encoding:NSUTF8StringEncoding],
            @"args_types": argsTypes,
        }];
        if (methodReturnType) {
            free(methodReturnType);
        }
    }
    if (methods) {
        free(methods);
    }

    NSData *data = [NSJSONSerialization dataWithJSONObject:classDescription options:0 error:nil];
    [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}
"""

OBJC_OBJECT_DUMP_SNIPPET = r"""
@import ObjectiveC;
@import Foundation;

unsigned int outCount = 0;
unsigned int i = 0;
id objcObject = (id)__symbol_address__;
Class objcClass = [objcObject class];
Class superClass;

if (!objcObject) {
    @"error: object is null";
} else {
    NSDictionary *objectData = @{
        @"protocols": [NSMutableArray new],
        @"ivars": [NSMutableArray new],
        @"properties": [NSMutableArray new],
        @"methods": [NSMutableArray new],
        @"class_name": [NSString stringWithCString:class_getName(objcClass) encoding:NSUTF8StringEncoding],
        @"class_address": [NSNumber numberWithUnsignedLongLong:(uintptr_t)objcClass],
        @"class_super": [NSNumber numberWithLong:(uintptr_t)class_getSuperclass(objcClass)],
    };

    id *protocolList = class_copyProtocolList(objcClass, &outCount);
    for (i = 0; i < outCount; ++i) {
        [objectData[@"protocols"] addObject: 
            [NSString stringWithCString:protocol_getName(protocolList[i]) encoding:NSUTF8StringEncoding]];
    }
    if (protocolList) {
        free(protocolList);
    }

    Ivar *ivars = class_copyIvarList(objcClass, &outCount);
    NSString *ivarName;
    for (i = 0; i < outCount; ++i) {
        ivarName = [NSString stringWithCString:ivar_getName(ivars[i]) encoding:NSUTF8StringEncoding];
        [objectData[@"ivars"] addObject:@{
            @"name": ivarName,
            @"value": [NSNumber numberWithUnsignedLongLong:(uintptr_t)object_getIvar(objcObject, ivars[i])],
            @"type": [NSString stringWithCString:ivar_getTypeEncoding(ivars[i]) encoding:NSUTF8StringEncoding],
            @"offset": [NSNumber numberWithInt:ivar_getOffset(ivars[i])],
        }];
    }
    if (ivars) {
        free(ivars);
    }

    for (superClass = class_getSuperclass(objcClass); superClass; superClass = class_getSuperclass(superClass)) {
        ivars = class_copyIvarList(superClass, &outCount);
        for (i = 0; i < outCount; ++i) {
            ivarName = [NSString stringWithCString:ivar_getName(ivars[i]) encoding:NSUTF8StringEncoding];
            [objectData[@"ivars"] addObject:@{
                @"name": ivarName,
                @"value": [NSNumber numberWithUnsignedLongLong:(uintptr_t)object_getIvar(objcObject, ivars[i])],
                @"type": [NSString stringWithCString:ivar_getTypeEncoding(ivars[i]) encoding:NSUTF8StringEncoding],
                @"offset": [NSNumber numberWithInt:ivar_getOffset(ivars[i])],
            }];
        }
        if (ivars) {
            free(ivars);
        }
    }

    NSData *data = [NSJSONSerialization dataWithJSONObject:objectData options:0 error:nil];
    [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}
"""


def _escape_objc_string(value: str) -> str:
    # NOTE: This is a basic escaper. It does not handle all edge cases (e.g. newlines, format strings).
    # Ensure `value` comes from a trusted source or is strictly validated before
    # using it in `stringWithFormat:` or similar contexts to avoid injection.
    return value.replace("\\", "\\\\").replace('"', '\\"')


def runtime_objc_class_dump(
    director: LLDBDirector,
    class_name: str | None = None,
    address: str | None = None,
) -> str:
    """Dump full ObjC class description (methods, ivars) as JSON."""
    # TODO(phase2): Pre-compile/inject this helper to avoid JIT cost per call.
    if not class_name and not address:
        return "Error: provide class_name or address"

    addr_expr = "0x0"
    if address:
        addr_val = director.evaluate_address(address)
        if addr_val is None:
            return f"Error: could not parse address from '{address}'"
        addr_expr = f"0x{addr_val:x}"

    name_value = _escape_objc_string(class_name) if class_name else ""
    expr = OBJC_CLASS_DUMP_SNIPPET.replace("__class_address__", addr_expr).replace("__class_name__", name_value)
    cmd = "expression -l objc -O -- " + " ".join(expr.split())
    return director.execute_lldb_command(cmd)


def runtime_objc_object_dump(director: LLDBDirector, address: str) -> str:
    """Dump ObjC instance details (ivars with values) as JSON."""
    addr_val = director.evaluate_address(address)
    if addr_val is None:
        return f"Error: could not parse address from '{address}'"
    addr_expr = f"0x{addr_val:x}"

    expr = OBJC_OBJECT_DUMP_SNIPPET.replace("__symbol_address__", addr_expr)
    cmd = "expression -l objc -O -- " + " ".join(expr.split())
    return director.execute_lldb_command(cmd)
