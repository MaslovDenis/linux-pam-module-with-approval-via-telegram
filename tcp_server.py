import json
import socket
import telebot
from telebot import types
import argparse

parser = argparse.ArgumentParser()

""" Set the arguments """

parser.add_argument('--bind-address', '-ip',
                    help='Server ip',
                    default='127.0.0.1')
parser.add_argument('--bind-port', '-p',
                    help='Server port',
                    default='8686')
parser.add_argument('--api-token', '-t',
                    help='Telegram API token',
                    required=True)
parser.add_argument('--approver', '-a',
                    help='Telegram user id for approve',
                    required=True)

args = parser.parse_args()


def main():
    """Configuring the socket """
    # todo TLS
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((args.bind_address, int(args.bind_port)))
    server_socket.listen(10)
    print('server is running, please, press ctrl+c to stop')

    """ Listening to requests """
    try:
        while True:
            connection, address = server_socket.accept()
            print("new connection from {address}".format(address=address))

            """ receive data from the client """
            data = connection.recv(1024)

            if data:
                data = json.loads(data)

                """ initialization of telegram bot """
                bot = telebot.TeleBot(args.api_token)

                """ initialization of telegrams of the keyboard """
                kb_admin = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True, row_width=2)
                kb_admin.add(types.KeyboardButton("Approve ✅"))
                kb_admin.add(types.KeyboardButton("Reject ❌"))

                """ sending a message to the approver """
                send = bot.send_message(
                    args.approver,
                    f'User *{data["user"]}* requests access to server: *{data["host"]}*',
                    reply_markup=kb_admin, parse_mode="Markdown"
                )

                """ sending the confirmation result to the client """
                bot.register_next_step_handler(
                    send,
                    callback=message_reply,
                    connection=connection,
                    bot=bot,
                )

                """ stop telegram bot """
                bot.polling()

            """ closing tcp connection """
            connection.close()
    except Exception as e:
        print(f"ERROR: {e}")
        connection.close()


def message_reply(message, connection, bot):
    """ sending the confirmation result to the client """

    if "Approve" in message.text:
        connection.send(bytes('Approve', encoding='UTF-8'))
    elif "Reject" in message.text:
        connection.send(bytes('Reject', encoding='UTF-8'))

    bot.send_message(args.approver, text='', reply_markup=types.ReplyKeyboardRemove())
    bot.stop_polling()


if __name__ == "__main__":
    main()
