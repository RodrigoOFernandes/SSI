
import asyncio
from asyncio import StreamReader,StreamWriter

class Connection:
    """Handles the details of connection client-server"""
    def __init__(self,host:str,port:str,conn_id : int = None,reader = None,writer=None):
        self.id = conn_id
        self.host = host
        self.port = port
        self.reader = reader
        self.writer = writer
        self.msg_cnt = 0
        self.maxSize = 9999
    
    async def shutdown_server(self):
        """Encerra o servidor após um breve atraso para permitir envio da resposta final"""
        await asyncio.sleep(2)  # Pequeno atraso para garantir que as respostas sejam enviadas
        print("Shutting down server...")
        # Obter a referência ao loop e ao servidor
        for task in asyncio.all_tasks():
            if task is not asyncio.current_task():
                task.cancel()
        asyncio.get_event_loop().stop()


    async def sendRaw(self,data:bytes) -> bool:
        """Send raw bytes of data"""
        if not self.writer:
            return False
        try:
            self.writer.write(data)
            await self.writer.drain()
            return True
        except Exception as e:
            print(f'Exception - {e}')
            return False

    async def recvRaw(self) -> bytes:
        """Receive raw bytes of data"""
        if not self.reader:
            return None
        
        try:
            return await self.reader.read(self.maxSize)
        except Exception:
            return None

        

    async def connect(self) -> tuple[StreamReader,StreamWriter]:
        """
        Establish connection with the server
        Returns:
            - Tuple read, write stream sock

        """
        try:
            self.reader,self.writer = await asyncio.open_connection(
                self.host,self.port
            )
            if self.reader and self.writer:
                return self.reader,self.writer
        except ConnectionRefusedError:
            print(f"Connection refused. Make sure the server is running at {self.host}:{self.port}")
            return None
        except Exception as e:
            print(f"Connection error: {e}")
            return None

    async def recvMessage(self):
        """
            This method is meant to receive normal strings
        """
        try:
            msg : bytes = await self.recvRaw()
            if msg:
                self.msg_cnt += 1
                return msg.decode()
            
        except Exception as e:
            print(f'Error in Connection.recvRaw() - {e}')
        
    async def sendMessage(self,message : str):
        """
            Send normal strings and account for authentication
        """
        try:
            self.msg_cnt += 1

            if not await self.sendRaw(message.encode()):
                return None
            
            return True


        
        except Exception as e:
            print(f'Error in Connection.sendMessage() - {e}')
            return None

    async def close(self):
        """
            Close the communication socket
        """
        if self.writer:
            try:
                #await self.sendRaw(b'\n')
                self.writer.close()
                print('Connection closed completely')

            except Exception as e:
                print(f'Error in Connection.close() - {e}')
