import ast
import operator

_OP_MAP = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}


def safe_eval(expr_str: str, x_val: float) -> float:
    def _eval(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id == 'x':
            return x_val
        if isinstance(node, ast.BinOp):
            return _OP_MAP[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp):
            return _OP_MAP[type(node.op)](_eval(node.operand))
        raise ValueError(f"Unsupported syntax in expression: {expr_str}")

    tree = ast.parse(expr_str, mode='eval')
    return _eval(tree.body)


def decode_bytes(data: bytes, offset: int, length: int, endian: str) -> int:
    chunk = data[offset:offset + length]
    if endian == "big":
        return int.from_bytes(chunk, byteorder='big')
    return int.from_bytes(chunk, byteorder='little')


def parse_parameters(data: bytes, table_config: dict) -> dict:
    results = {}
    for name, param in table_config.get("parameters", {}).items():
        raw = decode_bytes(
            data,
            param["offset"],
            param["length"],
            param.get("endian", "big"),
        )
        value = safe_eval(param["formula"], raw)
        results[name] = {
            "raw": raw,
            "value": value,
            "unit": param.get("unit", ""),
        }
    return results
