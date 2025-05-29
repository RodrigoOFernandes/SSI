import re

class Commands:
    COMMANDS = {
        'add': re.compile(r'^add\s\S+$'),
        'list': re.compile(r'^list\s-[ug]\s\S+$'),
        'share': re.compile(r'^share\s\S+\s\S+\s[rw]$'),
        'delete': re.compile(r'^delete\s\S+$'),
        'replace': re.compile(r'^replace\s\S+\s\S+$'),
        'details': re.compile(r'^details\s\S+$'),
        'revoke': re.compile(r'^revoke\s\S+\s\S+$'),
        'read': re.compile(r'^read\s\S+$'),
        'group_create': re.compile(r'^group\screate\s\S+$'),
        'group_delete_user': re.compile(r'^group\sdelete-user\s\S+\s\S+$'), 
        'group_delete': re.compile(r'^group\sdelete\s\S+$'),
        'group_add_user': re.compile(r'^group\sadd-user\s\S+\s\S+\s\S+$'),
        'group_list': re.compile(r'^group\slist$'),
        'group_add': re.compile(r'^group\sadd\s\S+\s\S+$'),
        'exit': re.compile(r'^exit$'),
        'exitSHUTDOWN': re.compile(r'^exitSHUTDOWN$')
    }

    @classmethod
    def validate(cls, command):
        if not command.strip():
            return False, "Empty command"

        parts = command.split()
        base_cmd = parts[0]

        if base_cmd == 'group' and len(parts) > 1:
            sub_cmd = parts[1]
            full_cmd = f"group_{sub_cmd.replace('-', '_')}"

            if full_cmd in cls.COMMANDS:
                if cls.COMMANDS[full_cmd].match(command):
                    return True, "OK"
                return False, f"Invalid format for: '{command}'"

        if base_cmd in cls.COMMANDS:
            if cls.COMMANDS[base_cmd].match(command):
                return True, "OK"
            return False, f"Invalid format for: '{base_cmd}'" 

        return False, f"Unknown command: {base_cmd}"

