import threading
from tcp_by_size import  send_with_size

class AsyncMessages:
    """
        this class provide global messages area for server that handle multi clients by threads
        it enables many threads to communicate by one dictionary (self.async_msgs)
        each thread might put data to specific other thread (the key is the other thread socket)
        each thread can get his messages by his socket
        this class is thread safe
    """

    def __init__(self):
        self.conn = None
        self.lock_async_msgs = threading.Lock()
        self.async_msgs = {}

    def add_new_user(self,username):
        """
            call to this method right after socket accept with client socket
        """
        self.async_msgs[username] = []

    def delete_user(self, username):
        del self.async_msgs[username]


    def put_msg_by_user(self, user, data):
        self.lock_async_msgs.acquire()
        self.async_msgs[user].append(data)
        self.lock_async_msgs.release()

    def put_msg_to_all(self, data):
        self.lock_async_msgs.acquire()
        for username in self.async_msgs.keys():
            self.async_msgs[username].append(data)
        self.lock_async_msgs.release()

    def get_async_messages_to_send(self, username):
        msgs = []
        if self.async_msgs[username] != []:
            self.lock_async_msgs.acquire()
            msgs = self.async_msgs[username]

            self.async_msgs[username] = []
            self.lock_async_msgs.release()
        return msgs
