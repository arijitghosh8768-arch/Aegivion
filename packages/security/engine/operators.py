from typing import Any, List, Dict
import re

class OperatorRegistry:
    """Registry of all available operators"""
    
    _operators = {}
    
    @classmethod
    def register(cls, name: str, func):
        cls._operators[name] = func
    
    @classmethod
    def get_operator(cls, name: str):
        return cls._operators.get(name)
    
    @classmethod
    def get_operators(cls) -> List[str]:
        return list(cls._operators.keys())
    
    @classmethod
    def execute(cls, operator: str, field_value: Any, condition_value: Any) -> bool:
        """Execute an operator"""
        func = cls.get_operator(operator)
        if not func:
            raise ValueError(f"Unknown operator: {operator}")
        return func(field_value, condition_value)

# Register standard operators
def op_equals(field: Any, value: Any) -> bool:
    return field == value

def op_not_equals(field: Any, value: Any) -> bool:
    return field != value

def op_exists(field: Any, value: Any) -> bool:
    return field is not None

def op_not_exists(field: Any, value: Any) -> bool:
    return field is None

def op_contains(field: Any, value: Any) -> bool:
    if isinstance(field, (list, str)):
        return value in field
    return False

def op_not_contains(field: Any, value: Any) -> bool:
    if isinstance(field, (list, str)):
        return value not in field
    return True

def op_greater_than(field: Any, value: Any) -> bool:
    try:
        return float(field) > float(value)
    except:
        return False

def op_less_than(field: Any, value: Any) -> bool:
    try:
        return float(field) < float(value)
    except:
        return False

def op_in(field: Any, value: List) -> bool:
    return field in value

def op_not_in(field: Any, value: List) -> bool:
    return field not in value

def op_regex(field: Any, value: str) -> bool:
    try:
        return bool(re.match(value, str(field)))
    except:
        return False

def op_network_exposure(field: Any, value: Any) -> bool:
    # Special operator evaluated directly by RuleExecutor
    return False

# Register all operators
OperatorRegistry.register("equals", op_equals)
OperatorRegistry.register("not_equals", op_not_equals)
OperatorRegistry.register("exists", op_exists)
OperatorRegistry.register("not_exists", op_not_exists)
OperatorRegistry.register("contains", op_contains)
OperatorRegistry.register("not_contains", op_not_contains)
OperatorRegistry.register("greater_than", op_greater_than)
OperatorRegistry.register("less_than", op_less_than)
OperatorRegistry.register("in", op_in)
OperatorRegistry.register("not_in", op_not_in)
OperatorRegistry.register("regex", op_regex)
OperatorRegistry.register("network_exposure", op_network_exposure)
