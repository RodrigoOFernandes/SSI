import json
import os

def get_client_file(base_path,id):
    return f'{base_path}{id}.json'


def get_json_format(obj:object):
    return json.dumps(obj,indent=4)

def createUserFile(path):
    """Creates a blank file for a user"""
    if not os.path.isfile(path):
            os.system(f'touch {path}')
            with open(path,"w") as file:
                default = {
                    "files":{},
                    "counter":0
                }
                file.write(get_json_format(default))

class ClientStore:
    def __init__(self,id:str,path:str = None):
        # Store user id
        self.id = id

        # Load the root_file_path to memory
        with open("./config.json",'r') as file:
            root = json.loads(file.read())
            self.root_file_path = root["root_file_path"]
        
        # Create file root folder if there isn't one 
        if not os.path.isdir(self.root_file_path):
            os.makedirs(self.root_file_path)

        # Load indicated keystore
        if not path:
            path = get_client_file(self.root_file_path,self.id)

        # Creats a blanck user file
        createUserFile(get_client_file(self.root_file_path,self.id))

        # Load the keystore from user json file
        with open(path,"r") as file:
            self.keystore : dict = json.loads(file.read())
        
    # Save keystore
    def save(self):
        with open(get_client_file(self.root_file_path,self.id),"w") as file:
            file.write(get_json_format(self.keystore))

    # Load keystore
    def load(self):
        with open(get_client_file(self.root_file_path,self.id),"r") as file:
            json.loads(file.read())

    """Main features"""

    # Insert new file
    def insert_file(self,id:str,key:bytes):
        # Check if the file exists
        if self.keystore["files"].get(id):
            return 'Alredy exists'
        # Associate key to value
        self.keystore["files"][id] = key
        # Increment the counter
        self.keystore["counter"] += 1
        # Save to file
        self.save()
        return 'Done'

    # Get file
    def get_file(self,id:str): # Done
        return self.keystore["files"].get(id)

    # Update file
    def update_file(self,id,key): # Done
        if self.keystore["files"].get(id):
            self.keystore["files"][id] = key
            self.save()
            return 'Done'
        return 'File ID was not found'

    # Delete file
    def delete_file(self,id): # Done
        if self.keystore["files"].get(id):
            del self.keystore["files"][id]
            self.keystore["counter"] = len(self.keystore["files"])
            self.save()
            return 'Deleted'
        return 'The file does not exist'


# if __name__ == '__main__':
#     manager = ClientStore('VAULT_CLI1')
#     op = input()
#     match op:
#         case '1':
#             print(manager.insert_file('VAULT_CLI1_4','vff_super_secret_key'))
#         case '2':
#             print(manager.update_file('VAULT_CLI1_4','interface benta'))
#         case '3':
#             print(manager.get_file('VAULT_CLI1_4'))
#         case '4':
#             print(manager.delete_file('VAULT_CLI1_4'))