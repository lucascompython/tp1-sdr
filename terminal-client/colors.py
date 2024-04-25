class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    UNDERLINE = "\033[4m"
    BOLD = "\033[1m"
    ITALIC = "\033[3m"

    @staticmethod
    def color_underline_user(username: str, msg, color: str) -> str:
        return f"{Colors.UNDERLINE + color + username + Colors.RESET + color} {msg}{Colors.RESET}"
