import time
import sys
import hashlib
import telebot
import cherrypy
import pickledb
from telebot import apihelper
from telebot import types
import config
import constants

bot = telebot.TeleBot(config.TOKEN)

# WebhookServer, process webhook calls
class WebhookServer(object):
    @cherrypy.expose
    def index(self):
        if 'content-length' in cherrypy.request.headers and \
           'content-type' in cherrypy.request.headers and \
           cherrypy.request.headers['content-type'] == 'application/json':
            length = int(cherrypy.request.headers['content-length'])
            json_string = cherrypy.request.body.read(length).decode("utf-8")
            update = telebot.types.Update.de_json(json_string)
            bot.process_new_updates([update])
            return ''
        else:
            raise cherrypy.HTTPError(403)

# Checkin if user is accepted
def is_user_accepted(userid):
    userid = str(userid)
    if userid != config.MY_USERID:
        # result = pdb.get()
        try:
            pdb_req = pdb.get('accepted_users')
            if userid in pdb_req:
                return True
            return pdb_req
        except TypeError:
            return False
        except KeyError:
            return False
    else:
        return True

# Count rubles for lessons
def count_bill():
    pdb_req = pdb.get('lessons')
    if pdb_req != False:
        return '💵 Заплатить Ксении нужно {} рублей до мая'.format(pdb_req * config.ONE_LESSON)
    else:
        return 'Пока не нужно платить...'

# Proxy settings
def proxy_settings(sysargs):
    if len(sysargs) == 1:
        print('Booting without proxy.')
    else:
        if sysargs[1] == 'proxy':
            print('Booting with proxy.')
            apihelper.proxy = {'https': config.PROXYLIST[0]}
        else:
            print('Use "python3 main.py proxy" or "python3 main.py"')
            print('Closing...')
            sys.exit()

# Logging into file
def logging(message):
    if message.chat.id != config.MY_USERID:
        with open('log.log', 'a') as f:
            f.write(str(message.json) + '\n')


@bot.message_handler(commands=['start', 'help'], func=lambda message: is_user_accepted(message.chat.id))
def show_help(message):
    if message.chat.id == config.MY_USERID:
        bot.send_message(message.chat.id, constants.HELP_MESSAGE_FOR_ME)
    else:
        bot.send_message(message.chat.id, constants.HELP_MESSAGE.format(message.from_user.first_name))
    logging(message)


@bot.message_handler(commands=['checkbill'], func=lambda message: is_user_accepted(message.chat.id))
def show_bill(message):
    bot.send_message(message.chat.id, count_bill())
    logging(message)


@bot.message_handler(commands=['settings'], func=lambda message: is_user_accepted(message.chat.id))
def show_settings(message):
    bot.send_message(message.chat.id, 'Настройки')
    logging(message)


@bot.message_handler(commands=['pohod'], func=lambda message: message.chat.id == config.MY_USERID)
def show_pohod_keyboard(message):
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton('Сходил 👍', callback_data='called_on'),
        types.InlineKeyboardButton('Отмена ❌', callback_data='cancel'))
    
    pdb.set('bill_message_id', message.message_id + 1)

    bot.send_message(message.chat.id, 'Сходил?', reply_markup=keyboard)


@bot.callback_query_handler(func=lambda call: call.data in ['called_on', 'cancel'] and call.message.chat.id == config.MY_USERID)
def plus_one_lesson(call):
    b_message_id = pdb.get('bill_message_id')
    if call.message.message_id == b_message_id:
        if call.data == 'called_on':
            pdb_req = pdb.get('lessons')
            if pdb_req != False:
                pdb_req += 1
                pdb.set('lessons', pdb_req)
            else:
                pdb.set('lessons', 1)
            
            pdb.rem('bill_message_id')

            bot.edit_message_text(count_bill(), call.message.chat.id, call.message.message_id)

            users_to_be_notified = pdb.get('accepted_users')
            if users_to_be_notified != False:
                for user in users_to_be_notified:
                    bot.send_message(user, count_bill())
        elif call.data == 'cancel':
            pdb.rem('bill_message_id')
            bot.edit_message_text('Отменил', call.message.chat.id, call.message.message_id)

    elif b_message_id == False:
        bot.edit_message_text('Прожми /pohod', call.message.chat.id, call.message.message_id)
    else:
        bot.edit_message_text('Посмотри последнее сообщение такого типа ', call.message.chat.id, call.message.message_id)


@bot.message_handler(commands=['getlog'], func=lambda message: message.chat.id == config.MY_USERID)
def get_log(message):  
    with open('log.log', 'rb') as f:
        log_hash = hashlib.sha256(str(f.read()).encode()).hexdigest()
    prev_log_hash = pdb.get('log_file_hash')
    if prev_log_hash == False:
        # No hash in db
        pdb.set('log_file_hash', log_hash)
        with open('log.log', 'rb') as f:
            bot.send_document(message.chat.id, f)
    else:
        if prev_log_hash == log_hash:
            bot.send_message(message.chat.id, 'Лог идентичен предыдущему')
        else:
            pdb.set('log_file_hash', log_hash)
            with open('log.log', 'rb') as f:
                bot.send_document(message.chat.id, f)


@bot.message_handler(commands=['delcode'], func=lambda message: message.chat.id == config.MY_USERID)
def delete_code(message):
    code = pdb.get('code')

    if code == False:
        bot.send_message(message.chat.id, 'Не было никакого кода. Хозяин, ты бредишь 🤦‍♂️')
        return 0
    else:
        pdb.rem('code')
        bot.send_message(message.chat.id, 'Код был: {}'.format(code))
        del code

@bot.message_handler(commands=['setcode'], func=lambda message: message.chat.id == config.MY_USERID)
def show_set_code_message(message):
    msg = bot.send_message(message.chat.id, 'Напиши код, который будет являться кодом доступа')
    bot.register_next_step_handler(msg, setting_code)


def setting_code(message):
    pdb.set('code', message.text)
    bot.send_message(message.chat.id, 'Установлен код: {}'.format(message.text))


@bot.message_handler(func=lambda message: is_user_accepted(message.chat.id) == False)
def checking_code(message):
    result = pdb.get('code')
    if result != False and result == message.text:
        pdb.rem('code')
        
        if pdb.get('accepted_users') == False:
            pdb.dcreate('accepted_users')

        pdb.dadd('accepted_users', (message.chat.id, message.from_user.first_name))

        bot.send_message(config.MY_USERID, 'В круги присоеденился {}'.format(message.from_user.first_name))

        bot.reply_to(message, 'Код верный!')
        show_help(message)
    else:
        logging(message)

@bot.message_handler(func=lambda message: is_user_accepted(message.chat.id))
def i_dont_know(message):
    bot.reply_to(message, 'Я простой бот, который понимает лишь команды, расписанные по команде /help')
    logging(message)


if __name__ == '__main__':
    pdb = pickledb.load('main.pdb', True)
    #print(is_user_accepted('841163953'))
    #sys.exit()
    
    def main():
        try:
            print('Working...')
            bot.polling(none_stop=True)
        except OSError:
            print('Connection Error. Waiting 5 seconds...')
            time.sleep(5)
            main()

    # Setup cherry py server if it is needed
    for arg in sys.argv:
        if arg == 'webhook':
            print('Booting with webhook...')

            WEBHOOK_HOST = config.SERVER_NAME
            WEBHOOK_PORT = config.SERVER_PORT  # 443, 80, 88 or 8443 (port need to be 'open')
            WEBHOOK_LISTEN = '0.0.0.0'  # In some VPS you may need to put here the IP addr

            WEBHOOK_SSL_CERT = './webhook_cert.pem'  # Path to the ssl certificate
            WEBHOOK_SSL_PRIV = './webhook_pkey.pem'  # Path to the ssl private key

            # Quick'n'dirty SSL certificate generation:
            #
            # openssl genrsa -out webhook_pkey.pem 2048
            # openssl req -new -x509 -days 3650 -key webhook_pkey.pem -out webhook_cert.pem
            #
            # When asked for "Common Name (e.g. server FQDN or YOUR name)" you should reply
            # with the same value in you put in WEBHOOK_HOST

            WEBHOOK_URL_BASE = "https://%s:%s" % (WEBHOOK_HOST, WEBHOOK_PORT)
            WEBHOOK_URL_PATH = "/%s/" % (config.TOKEN)


            # Remove webhook, it fails sometimes the set if there is a previous webhook
            bot.remove_webhook()

            # Set webhook
            bot.set_webhook(url=WEBHOOK_URL_BASE + WEBHOOK_URL_PATH,
                            certificate=open(WEBHOOK_SSL_CERT, 'r'))

            # Disable CherryPy requests log
            access_log = cherrypy.log.access_log
            for handler in tuple(access_log.handlers):
                access_log.removeHandler(handler)

            # Start cherrypy server
            cherrypy.config.update({
                'server.socket_host'    : WEBHOOK_LISTEN,
                'server.socket_port'    : WEBHOOK_PORT,
                'server.ssl_module'     : 'builtin',
                'server.ssl_certificate': WEBHOOK_SSL_CERT,
                'server.ssl_private_key': WEBHOOK_SSL_PRIV
            })

            cherrypy.quickstart(WebhookServer(), WEBHOOK_URL_PATH, {'/': {}})
            break
    else:
        print('Booting without webhook...')
        proxy_settings(sys.argv)
        main()
