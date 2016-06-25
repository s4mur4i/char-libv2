import hipchat


class Hipchat(object):
    def __init__(self):
        # Key with permission to only send messages
        # self.hipster = hipchat.HipChat("6b96d19e779c460093f12c3e678978")
        # Key with permission to query rooms
        self.hipster = hipchat.HipChat("780d68546f911b2bd0c91fb4991c6e")

    def get_room(self, room_name):
        """
        This function returns a room object
        :param room_name: The name of the room
        :return: the room object
        """
        room = self.hipster.find_room(room_name)
        return room

    def send_msg_to_room(self, room_id, from_name, message, notify=False, message_color=None):
        """
        This function sends a message to a given room
        :param room_id: The room_id of the room to send
        :param from_name: the username to tell who the message originates from
        :param message: The message itself
        :param notify: Should a notify bubble be raised
        :param message_color: what color the message should be in
        :return: None
        """
        if message_color:
            self.hipster.message_room(room_id, from_name, message, color=message_color, notify=notify)
        else:
            self.hipster.message_room(room_id, from_name, message, notify=notify)

    def send_notification_to_developers(self, message, message_color):
        """
        Sends a notification to developer room
        :param message: the message to send to developers
        :param message_color: The color of the message
        :return: None
        """
        room = self.get_room(room_name="Xively DevOps Notifications")
        self.send_msg_to_room(from_name="Kerrigan", message=message, room_id=room['room_id'],
                              message_color=message_color)

    def send_notification_to_devops(self, message, message_color):
        """
        Sends a notification to devops room
        :param message: The message to send to devops
        :param message_color: The color of the message
        :return: None
        """
        room = self.get_room(room_name="DevOps Build")
        self.send_msg_to_room(from_name="Kerrigan", message=message, room_id=room['room_id'],
                              message_color=message_color)

    def send_notification_to_s4mur4i(self, message, message_color):
        """
        This function is used for sending test notifications to a private devops room
        :param message: The message to send to devops
        :param message_color: The color of the message
        :return: None
        """
        room = self.get_room(room_name="s4mur4i-test")
        self.send_msg_to_room(from_name="Kerrigan", message=message, room_id=room['room_id'],
                              message_color=message_color)

    def change_notification(self, message):
        """
        A message abount a change that is going to happen

        Currently in test function, messages sent to private room
        :param message: the message to send
        :return: None
        """
        self.send_notification_to_s4mur4i(message=message, message_color="yellow")
        #self.send_notification_to_devops(message=message, message_color="yellow")

    def change_done(self, message):
        """
        A message abount a change finished

        Currently in test function, messages sent to private room
        :param message: the message to send
        :return: None
        """
        self.send_notification_to_s4mur4i(message=message, message_color="green")
        #self.send_notification_to_devops(message=message, message_color="green")

    def anomaly_detected(self, message):
        """
        A message containing an anomally detected

        Currently in test function, messages sent to private room
        :param message: the message to send
        :return: None
        """
        self.send_notification_to_s4mur4i(message=message, message_color="red")
        #self.send_notification_to_devops(message=message, message_color="red")

    def normal_message(self, message):
        """
        A normal message to send to a group of users

        Currently in test function, messages sent to private room
        :param message: the message to send
        :return: None
        """
        self.send_notification_to_s4mur4i(message=message, message_color="gray")
        #self.send_notification_to_devops(message=message, message_color="gray")


hc = Hipchat()
