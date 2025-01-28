from GroupChat import GroupChat
if __name__ == "__main__":
    username = input("Enter your username: ")
    host = "127.0.0.1"  # Default host
    port = 5000

    chat = GroupChat(username, host, port)
    chat.run()
