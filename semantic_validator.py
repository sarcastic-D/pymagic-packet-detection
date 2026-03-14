from structure_validator import ValidationError

class SemanticValidator:
    def __init__(self, cond):
        self.cond = cond
        self.match = cond.get("match", {})
        self.protocols = cond.get("protocol")
        if isinstance(self.protocols, str):
            self.protocols = [self.protocols]
        self.protocols = [p.upper() for p in self.protocols]
        self.run_checks()

    def run_checks(self):
        tcp_fields = {"seq", "ack", "window_size", "tcp_option_value"}
        if "TCP" not in self.protocols:
            for k in tcp_fields:
                if k in self.match:
                    raise ValidationError(f"Field '{k}' requires TCP protocol")