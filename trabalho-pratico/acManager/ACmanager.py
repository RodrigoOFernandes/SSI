import json
import os

class ACmanager:
    def __init__(self, user_id: str):

        # Load configuration files
        # Load default permissions for the system
        with open("acManager/defaultPermissions.json", "r") as file:
            self.defaultPermissions = json.load(file)
        
        # Load the default structure of the server
        # Defines the filesystem folder locations
        # and users/groups/sharedFiles db files
        with open("acManager/baseStructure.json", "r") as file:
            self.baseStructure = json.load(file)
        
        # Loads the groups info from json
        with open(self.baseStructure["groups"], "r") as file:
            self.groups_data = json.load(file)
        
        # Loads the users info from json
        with open(self.baseStructure["users"], "r") as file:
            self.users_data = json.load(file)
        
        # Loads the shared files info from json
        with open(self.baseStructure["sharedFiles"], "r") as file:
            self.shared_files_data = json.load(file)
        
        # Initialize directory structure
        self._init_directory_structure()
        
        # Set active user
        self.active_user = user_id
        if self.users_data["users"]: self.user_data = self.users_data["users"].get(user_id)
        
        if not self.user_data:
            raise ValueError(f"User {user_id} not found")
    
    def _init_directory_structure(self):
        """Create necessary directories if they don't exist"""
        # Create personal folders for all users
        for user_id in self.users_data["users"]:
            user_dir = os.path.join(self.baseStructure["personal-folder"], user_id)
            os.makedirs(user_dir, exist_ok=True)
        
        # Create group folders
        for group_id in self.groups_data["groups"]:
            group_dir = os.path.join(self.baseStructure["groups-folder"], group_id)
            os.makedirs(group_dir, exist_ok=True)
    
    def find_user(self, user_id: str):
        return self.users_data["users"].get(user_id)
    
    def find_group(self, group_id: str):
        return self.groups_data["groups"].get(group_id)
    
    def find_group_by_name(self, group_name: str):
        """Find a group by its name (not ID)"""
        for group_id, group_data in self.groups_data["groups"].items():
            if group_data.get("name") == group_name:
                return group_id, group_data
        return None, None
    

    def loadShared(self):
        with open(self.baseStructure["sharedFiles"], "r") as file:
            self.shared_files_data = json.load(file)

    def find_file(self,filename:str):
        print(f'find_file called by {self.active_user}')
        """Find a file across personal, shared and group files"""
        # Check if it is a group file by checking the group id on the file_id
        for group_id in self.groups_data["groups"].keys():
            if filename.find(group_id) != -1:
                print(self.groups_data["groups"][group_id]["files"])
                return {
                    "type":"group",
                    "group_id":group_id,
                    "file_data":self.groups_data["groups"][group_id]["files"][filename],
                    "path":os.path.join(self.baseStructure["groups-folder"],
                                        group_id,filename)
                }
        # Check if it is a shared file by checking if the file is in the active 
        print(f'files - \n{self.shared_files_data["shared_files"]["personal"][self.active_user]["files"].keys()}')
        if filename in self.shared_files_data["shared_files"]["personal"][self.active_user]["files"].keys():
            shared_file = self.shared_files_data["shared_files"]["personal"][self.active_user]["files"][filename]
            return {
                "type":"shared",
                "file_data":shared_file,
                "path": os.path.join(self.baseStructure["personal-folder"],
                                     shared_file["owner"],filename)
            }
        # Check if it is a personal file
        if filename in self.user_data["personal_files"]:
            return {
                "type":"personal",
                "file_data":self.user_data["personal_files"][filename],
                "path": os.path.join(self.baseStructure["personal-folder"],
                                     self.active_user,filename)
            }
        # Otherwise return None
        return None

    def save_groups(self):
        """Writes the groups informations stored in the class state"""
        with open(self.baseStructure["groups"],"w") as file:
            file.write(json.dumps(self.groups_data,indent=4))

    def save_users(self):
        """Writes the users informations to the json persistance file"""
        with open(self.baseStructure["users"],"w") as file:
            file.write(json.dumps(self.users_data,indent=4))
    
    def save_shared(self):
        with open(self.baseStructure["sharedFiles"],"w") as file:
            file.write(json.dumps(self.shared_files_data,indent=4))

    def writeToFile(self,path:str,content):
        with open(path,"w") as file:
            file.write(content)

    def createUser(self,user_id:str):
        newUser = {
            "groups":[],
            "personal_files":{},
            "counter":0
        }

        self.users_data["users"][user_id] = newUser
        self.save_users()

    # Main features


    def add_file(self, content: str, file_id: str): # Done
        """Add a new personal file"""
        if not self.users_data:
            return None
        
        # Add file
        self.user_data["personal_files"][file_id] = {
            "permissions":{
                "read":True,
                "write":True
            }
        }
        
        self.writeToFile(self.find_file(file_id)["path"],content)

        self.user_data["counter"] += 1
        self.save_users()


    def get_file_id(self):
        file_id = self.active_user + '_' + str(self.user_data["counter"])
        return file_id



    # add <file-id>
    def _save_shared_files_data(self):
        """Salva os dados de arquivos compartilhados no arquivo JSON"""
        with open(self.baseStructure["sharedFiles"], "w") as file:
            json.dump(self.shared_files_data, file, indent=4)

    # Substitua o método share_file com uma implementação corrigida
    def share_file(self, filename: str, target_user: str, permissions: dict):
        """Share a file with another user"""
        file_info = self.find_file(filename)
        print(f"file found : {file_info}")
        if not file_info or file_info["type"] != "personal":
            print(f"Manager did not find file {filename}")
            return False
        
        # Check if target user exists
        target_user_data = self.find_user(target_user)
        if not target_user_data:
            print(f"Target user {target_user} not found")
            return False
        
        # Ensure personal structure exists
        if "personal" not in self.shared_files_data["shared_files"]:
            self.shared_files_data["shared_files"]["personal"] = {}
        
        # Ensure target user structure exists
        if target_user not in self.shared_files_data["shared_files"]["personal"]:
            self.shared_files_data["shared_files"]["personal"][target_user] = {"files": {}}
        
        # Add file to shared files for target user
        self.shared_files_data["shared_files"]["personal"][target_user]["files"][filename] = {
            "owner": self.active_user,
            "permissions": permissions
        }
        
        # Save changes
        self.save_shared()
        print(f"File {filename} shared with {target_user}")   
       
    # list [-u user-id | -g group-id ]
    def list_files(self, option: str = None, identifier: str = None): # Done
        """
        List files available for access based on the specified option.
        
        Args:
            option: "-u" for user files or "-g" for group files
            identifier: user-id or group-id to list files for
        
        Returns:
            Dictionary containing:
            - "personal": list of personal files
            - "shared": list of shared files
            - "groups": dictionary of {group_name: list_of_files}
        """
        result = {
            "personal": [],
            "shared": [],
            "groups": {}
        }
        
        # If no option specified, return all files the active user can access
        if option is None:
            # Personal files
            result["personal"] = list(self.user_data["personal_files"].keys())
            
            # Shared files
            if self.active_user in self.shared_files_data["shared_files"]["personal"]:
                result["shared"] = list(self.shared_files_data["shared_files"]["personal"][self.active_user]["files"].keys())
            
            # Group files
            for group_id in self.user_data["groups"]:
                group = self.find_group(group_id)
                if group:
                    result["groups"][group_id] = list(group["files"].keys())
            
            return result
        
        # Handle -u user-id option
        elif option == "-u":
            if identifier is None:
                identifier = self.active_user
            
            # Verify if the active user has permission to list these files
            if identifier == self.active_user:
                # Own files
                user = self.find_user(identifier)
                if user:
                    result["personal"] = list(user["personal_files"].keys())
                    
                    # Shared with this user
                    if identifier in self.shared_files_data["shared_files"]["personal"]:
                        result["shared"] = list(self.shared_files_data["shared_files"]["personal"][identifier]["files"].keys())
                    
                    # Group files
                    for group_id in user.get("groups", []):
                        group = self.find_group(group_id)
                        if group:
                            result["groups"][group_id] = list(group["files"].keys())
            
            return result
        
        # Handle -g group-id option
        elif option == "-g":
            if identifier is None:
                # List all groups the user belongs to
                for group_id in self.user_data["groups"]:
                    group = self.find_group(group_id)
                    if group:
                        result["groups"][group_id] = list(group["files"].keys())
            else:
                # Check if user is member of the specified group
                if identifier in self.user_data["groups"]:
                    group = self.find_group(identifier)
                    if group:
                        result["groups"][identifier] = list(group["files"].keys())
            
            return result
        
        return result
    
    def replace_content(self, filename: str, new_content: str): # Done
        """Replace file content if user has write permissions"""
        file_info = self.find_file(filename)
        if not file_info:
            return False
        
        # Check write permissions
        if file_info["type"] == "personal":
            has_permission = True  # Owner always has permission
        
        elif file_info["type"] == "shared":
            has_permission = file_info["file_data"]["permissions"].get("write", False)
        
        elif file_info["type"] == "group":
            group_id = file_info["group_id"]
            group = self.find_group(group_id)
            
            # Check if active user is owner
            if group["owner"] == self.active_user:
                has_permission = True
            # Check if active user is a member with write permission
            elif self.active_user in group["members"]:
                has_permission = group["members"][self.active_user].get("write", False)
            else:
                has_permission = False
        
        if has_permission:
            with open(file_info["path"], "w") as file:
                file.write(new_content)
            return True
        
        return False
    
    def file_details(self, filename: str):
        """Get detailed information about a file, including users with access and their permissions"""
        file_info = self.find_file(filename)
        if not file_info:
            return None
    
        details = {
            "filename": filename,
            "type": file_info["type"],
            "path": file_info["path"],
            "permissions": {},
            "users_with_access": {}
        }
    
        if file_info["type"] == "personal":
            details["owner"] = self.active_user
            details["permissions"] = self.user_data["personal_files"][filename]["permissions"]
        
            # Check shared access
            for user, data in self.shared_files_data["shared_files"]["personal"].items():
                if filename in data["files"]:
                    details["users_with_access"][user] = data["files"][filename]["permissions"]
    
        elif file_info["type"] == "shared":
            details["owner"] = file_info["file_data"]["owner"]
            details["permissions"] = file_info["file_data"]["permissions"]
        
            # Add the owner to the list of users with access
            details["users_with_access"][file_info["file_data"]["owner"]] = file_info["file_data"]["permissions"]
    
        elif file_info["type"] == "group":
            group_id = file_info["group_id"]
            group = self.find_group(group_id)
            details["group"] = group_id
            details["owner"] = group["owner"]
        
            # Get file permissions
            if "owner" in file_info["file_data"]:
                details["file_owner"] = file_info["file_data"]["owner"]
        
            # Determine permissions for active user
            if group["owner"] == self.active_user:
                # Group owner has full permissions
                details["permissions"] = {"read": True, "write": True}
            elif self.active_user in group["members"]:
                # Use member permissions
                details["permissions"] = group["members"][self.active_user]
            else:
                # Default permissions if not specified
                details["permissions"] = {"read": False, "write": False}
        
            # List all members with access
            for member, perms in group["members"].items():
                details["users_with_access"][member] = perms
    
        return details
    

    def readFile(self, fileId: str):
        """
        Read the contents of a file and return source flag and owner information
        Args:
            fileId: File to be read
        Returns:
            tuple: (content, flag, owner)
                - content: String with the file content
                - flag: 0 for personal, 1 for shared, 2 for group
                - owner: String with the owner's ID for group files, None otherwise
        """
        self.loadShared()
        file = self.find_file(fileId)
        content = None
        flag = None
        owner = None
        
        if file:
            # Determine flag baeed on file type
            if file["type"] == "personal":
                flag = 0
            elif file["type"] == "shared":
                flag = 1
                # Could optionally set owner here too if needed
                # owner = file["file_data"]["owner"]
            elif file["type"] == "group":
                flag = 2
                # Extract the owner of the file (not just the group)
                if "file_data" in file and "owner" in file["file_data"]:
                    owner = file["file_data"]["owner"]
                    
            # Read file content
            with open(file["path"], "r") as f:
                content = f.read()
                
        return content, flag, owner

    def debug(self):
        """Print current state for debugging"""
        print("Active User:", self.active_user)
        print("\nDefault Permissions:")
        print(json.dumps(self.defaultPermissions, indent=4))
        print("\nBase Structure:")
        print(json.dumps(self.baseStructure, indent=4))
        print("\nUser Data:")
        print(json.dumps(self.user_data, indent=4))
        print("\nGroups Data:")
        print(json.dumps(self.groups_data, indent=4))
        print("\nShared Files Data:")
        print(json.dumps(self.shared_files_data, indent=4))

    def deleteFile(self, file_id: str):
        # Find file
        file = self.find_file(file_id)
        if not file:
            print(f"File {file_id} not found")
            return False
            
        # if file is personal, remove from system and jsons
        match file["type"]:
            case 'personal': # done
                # Remove from the filesystem
                os.system(f'rm -f "{file["path"]}"')
                # Remove from users json
                del self.user_data["personal_files"][file_id]
                # Save users state
                self.user_data["counter"] -= 1
                self.save_users()
                # Remove permissions of other in shared files
                for user_id, user_data in list(self.shared_files_data["shared_files"]["personal"].items()):
                    if "files" in user_data and file_id in list(user_data["files"].keys()):
                        del user_data["files"][file_id]
                # Save shared files
                self.save_shared()
                return True
                
            case 'group': # Done until proven wrong
                group_id = file["group_id"]
                print(group_id)
                group = self.find_group(group_id)
                
                # if active user == file_owner or active_user == group_owner
                if self.active_user == group["owner"] or \
                   (file_id in group["files"] and 
                    "owner" in group["files"][file_id] and 
                    self.active_user == group["files"][file_id]["owner"]):
                    
                    # Remove from system
                    print(file["path"]) 
                    os.system(f'rm -f "{file["path"]}"')
                    # All users lose access as well
                    del group["files"][file_id]
                    
                    self.groups_data["groups"][group_id]["counter"] -= 1
                    self.save_groups()
                    return True
                else:
                    print("Permission denied: You are not the owner of this file or group")
                    return False
                    
            case 'shared': # Done until proven wrong
                if self.active_user in self.shared_files_data["shared_files"]["personal"] and \
                   file_id in self.shared_files_data["shared_files"]["personal"][self.active_user]["files"]:
                    del self.shared_files_data["shared_files"]["personal"][self.active_user]["files"][file_id]
                    self.save_shared()
                    return True
                return False
        
        return False

    # TODO: revoke file-id user-id
    def revoke(self, file_id, user_id):
        """Revoke shared access to a file from a specific user"""
        # Check if file exists and belongs to active user
        file_info = self.find_file(file_id)
        if not file_info or file_info["type"] != "personal":
            print(f"File {file_id} not found or is not a personal file")
            return False
            
        # Check if file is shared with the specified user
        if user_id in self.shared_files_data["shared_files"]["personal"] and \
           file_id in self.shared_files_data["shared_files"]["personal"][user_id]["files"]:
            
            # Remove file access for the user
            del self.shared_files_data["shared_files"]["personal"][user_id]["files"][file_id]
            self.save_shared()
            print(f"Access to file {file_id} revoked from user {user_id}")
            return True
        
        print(f"File {file_id} is not shared with user {user_id}")
        return False

    # Create a unique group ID based on name and group counter
    def _generate_group_id(self, group_name: str):
        """Generate a unique group ID based on name and counter"""
        # Initialize a group counter if it doesn't exist
        if "group_counter" not in self.groups_data:
            self.groups_data["group_counter"] = 0
            
        # Generate unique ID
        group_id = f"{group_name}_{self.groups_data['group_counter']}"
        
        # Increment counter
        self.groups_data["group_counter"] += 1
        
        return group_id

    # TODO: group create group-name
    def createGroup(self, group_name: str):
        """Create a new group with a unique ID based on the name"""
        # Check if a group with this name already exists
        group_id, _ = self.find_group_by_name(group_name)
        if group_id:
            print(f"A group with name '{group_name}' already exists")
            return None
        
        # Generate unique group ID
        group_id = self._generate_group_id(group_name)
        
        # Create group data
        self.groups_data["groups"][group_id] = {
            "name": group_name,
            "owner": self.active_user,
            "default_permissions": self.defaultPermissions,
            "members": {},
            "files": {},
            "counter": 0
        }
        
        # Create group directory
        os.makedirs(self.baseStructure["groups-folder"] + group_id, exist_ok=True)
        self.save_groups()

        # Add group to user's groups
        self.user_data["groups"].append(group_id)
        self.save_users()
        
        return group_id

    # TODO: group delete group-id
    def deleteGroup(self, group_id: str):
        """Delete a group if the active user is the owner"""
        group = self.find_group(group_id)
        if not group:
            print(f"Group {group_id} not found")
            return False
            
        if self.active_user != group["owner"]:
            print("Permission denied: You are not the owner of this group")
            return False
            
        # Remove group ID from all members
        for user_id in list(group["members"].keys()):
            if user_id in self.users_data["users"] and group_id in self.users_data["users"][user_id]["groups"]:
                self.users_data["users"][user_id]["groups"].remove(group_id)
        
        # Remove group from active user's groups
        if group_id in self.user_data["groups"]:
            self.user_data["groups"].remove(group_id)
            
        # Save users state
        self.save_users()
        
        # Delete group directory and files
        os.system(f'rm -rf "{self.baseStructure["groups-folder"] + group_id}"')
        
        # Delete group from database
        del self.groups_data["groups"][group_id]
        
        # Save groups state
        self.save_groups()
        
        print(f"Group {group_id} deleted successfully")
        return True

    # TODO: group add-user group-id user-id permissions
    def groupAddUser(self, group_id: str, user_id: str, permissions: dict):
        """Add a user to a group with specified permissions"""
        group = self.find_group(group_id)
        if not group:
            print(f"Group {group_id} not found")
            return False
            
        # Check if active user is the group owner
        if self.active_user != group["owner"]:
            print("Permission denied: Only group owner can add members")
            return False
            
        # Check if target user exists
        target_user = self.find_user(user_id)
        if not target_user:
            print(f"User {user_id} not found")
            return False
            
        # Add user to group members
        group["members"][user_id] = permissions
        self.save_groups()
        
        # Add group to user's groups
        if group_id not in self.users_data["users"][user_id]["groups"]:
            self.users_data["users"][user_id]["groups"].append(group_id)
            self.save_users()
        
        print(f"User {user_id} added to group {group_id}")
        return True

    # TODO: group delete-user group-id user-id
    def groupDeleteUser(self, group_id: str, user_id: str):
        """Remove a user from a group"""
        group = self.find_group(group_id)
        if not group:
            print(f"Group {group_id} not found")
            return False
            
        # Check if active user is the group owner
        if self.active_user != group["owner"]:
            print("Permission denied: Only group owner can remove members")
            return False
            
        # Check if user is a member
        if user_id not in group["members"]:
            print(f"User {user_id} is not a member of group {group_id}")
            return False
            
        # Remove user from group members
        del group["members"][user_id]
        self.save_groups()
        
        # Remove group from user's groups
        if user_id in self.users_data["users"] and group_id in self.users_data["users"][user_id]["groups"]:
            self.users_data["users"][user_id]["groups"].remove(group_id)
            self.save_users()
        
        print(f"User {user_id} removed from group {group_id}")
        return True

    # TODO: group list
    def groupList(self) -> list:
        """List all groups the active user belongs to or owns, including permissions"""
        groups_info = []

        # Iterar sobre todos os grupos no arquivo groups.json
        for group_id, group_data in self.groups_data["groups"].items():
            is_owner = group_data["owner"] == self.active_user
            is_member = self.active_user in group_data.get("members", {})

            # Adicionar o grupo apenas se o utilizador for o dono ou membro
            if is_owner or is_member:
                # Determinar permissões
                if is_owner:
                    permissions = {"read": True, "write": True}  # Dono tem todas as permissões
                elif is_member:
                    permissions = group_data["members"].get(self.active_user, group_data["default_permissions"])
                else:
                    permissions = group_data["default_permissions"]

                # Adicionar informações do grupo
                groups_info.append({
                    "id": group_id,
                    "name": group_data.get("name", group_id),
                    "owner": group_data["owner"],
                    "is_owner": is_owner,
                    "member_count": len(group_data.get("members", {})),
                    "file_count": len(group_data.get("files", {})),
                    "permissions": permissions
                })

        return groups_info

    # TODO: group add group-id file-path
    def groupAddFile(self, file_id, group_id: str, content: str):
        """Add a file to a group"""
        group = self.find_group(group_id)
        if not group:
            print(f"Group {group_id} not found")
            return None
            
        # Check if user has write permission
        has_permission = False
        
        # Group owner always has permission
        if self.active_user == group["owner"]:
            has_permission = True
        # Check member permissions
        elif self.active_user in group["members"] and group["members"][self.active_user].get("write", False):
            has_permission = True
            
        if not has_permission:
            print("Permission denied: You don't have write access to this group")
            return None
            
        # Add file to group files
        group["files"][file_id] = {
            "owner": self.active_user,
            "permissions": self.defaultPermissions
        }
        
        # Write file content
        file_path = os.path.join(self.baseStructure["groups-folder"], group_id, file_id)
        with open(file_path, "w") as file:
            file.write(content)
            
        # Increment group counter
        group["counter"] += 1
        
        # Save groups data
        self.save_groups()
        
        print(f"File {file_id} added to group {group_id}")

    def get_group_file_id(self, group_id):
        group = self.find_group(group_id)
        file_id = f"{group_id}_{self.active_user}_{group['counter']}"
        return file_id

    def get_group_members(self, group_id: str):
        """Retrieve all members of a specific group along with their permissions.
        
        Args:
            group_id: The ID of the group to get members from
            
        Returns:
            A dictionary containing:
            - "owner": The group owner's user ID
            - "members": Dictionary of members and their permissions
            - "default_permissions": The group's default permissions
            Or None if group doesn't exist
        """
        group = self.find_group(group_id)
        if not group:
            print(f"Group {group_id} not found")
            return None
        
        return list(group.get("members", {}).keys())

    def debugObject(self, info):
        print(json.dumps(info, indent=4))


if __name__=="__main__":
    manager = ACmanager("VAULT_CLI1")

    manager.debugObject(manager.find_file("VAULT_CLI1_0"))
