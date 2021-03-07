import sys,os,json,base64,configparser,frozen_dir
import webbrowser,requests,threading

from Gui.main import Ui_MainWindow
from Gui.key_Settings import Ui_Form
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import *
from datetime import datetime
from shodan import Shodan
import eventlet
from PyQt5.QtGui import *
if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH']
Version = 'V1.2'
SETUP_DIR = frozen_dir.app_path()
sys.path.append(SETUP_DIR)
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}
class MainWindows(QtWidgets.QMainWindow,Ui_MainWindow):
    def __init__(self,parent=None):
        super(MainWindows,self).__init__(parent)
        self.Ui = Ui_MainWindow()
        self.Ui.setupUi(self)
        self.setWindowTitle('漏洞目标采集工具 '+Version+' By qianxiao996 ')
        self.setWindowIcon(QtGui.QIcon('./logo.ico'))
        self.shodan_key = ''
        self.censys_API_ID = ''
        self.censys_Secret = ''
        self.fofa_email = ''
        self.fofa_key =''
        self.fofa_api=''
        self.zoomeye_username = ''
        self.zoomeye_password = ''
        self.zoomeye_access_token=  ''
        self.file_config()
        self.Ui.actionKEY.triggered.connect(self.open_key_settings)
        self.Ui.action_about.triggered.connect(self.about)
        self.Ui.action_update.triggered.connect(self.version_update)
        self.Ui.action_clean.triggered.connect(self.clear)
        self.Ui.action_save.triggered.connect(self.save_result)
        self.Ui.pushButton_save.clicked.connect(self.save_result)
        self.Ui.pushButton_start.clicked.connect(self.start)
        self.Ui.action_start.triggered.connect(self.start)
    #     self.Ui.comboBox_type.activated[str].connect(self.shodan_settings)
    # #shodan去掉页数
    # def shodan_settings(self):
    #     if self.Ui.comboBox_type.currentText()=="Shodan" :
    #         self.Ui.spinBox_num.setEnabled(False)
    #     else:
    #         self.Ui.spinBox_num.setEnabled(True)
    def start(self):
        text= self.Ui.lineEdit_text.text()
        page = self.Ui.spinBox_num.value()
        if text!='':
            type =  self.Ui.comboBox_type.currentText()
            self.Ui.textEdit_result.clear()
            self.Ui.textEdit_log.clear()

            if type=="FOFA":
                thread1 = threading.Thread(target=self.FOFA_start, args=(text,page))
                thread1.setDaemon(True)
                thread1.start()
            if type=="Shodan":
                thread2 = threading.Thread(target=self.Shodan_start, args=(text, page))
                thread2.setDaemon(True)
                thread2.start()
            if type=="Censys":
                thread3 = threading.Thread(target=self.Censys_start, args=(text, page))
                thread3.setDaemon(True)
                thread3.start()
            if type=="ZoomEye":
                thread4 = threading.Thread(target=self.ZoomEye_start, args=(text, page))
                thread4.setDaemon(True)
                thread4.start()
        else:
            self.Ui.textEdit_log.append(self.getTime()+'未填写关键字!')
    def FOFA_start(self,text,all_page):
        self.Ui.action_start.setEnabled(False)
        self.Ui.pushButton_start.setEnabled(False)
        try:
            text= text.encode(encoding="utf-8")
            text = base64.b64encode(text).decode()
            for page in range(all_page):
                data = ''
                # print(bcolors.red)
                page = page + 1
                self.Ui.textEdit_log.append(self.getTime() + '开始查询第%s页...' % page)
                url = self.fofa_api.replace('${FOFA_EMAIL}',self.fofa_email).replace('${FOFA_KEY}',self.fofa_key).replace('${FOFA_PAGE}',str(page)).replace('${FOFA_BASE64}',text)
                # print(url)
                timeout = int(self.Ui.comboBox_timeout.currentText())
                req = requests.get(url, headers=headers, timeout=timeout ,verify=False)
                req = req.text
                # print(req)
                try:
                    req = json.loads(req)['results']
                    self.Ui.textEdit_log.append(self.getTime() +"共获取到%s条数据"%len(req))
                    for i in range(len(req)):
                        data += req[i][0] + '\n'
                    self.result_adddata(data.strip())
                    if len(req)<100:
                        break
                        # print(data)#
                except Exception as e:
                    # print(e)
                    error2 = json.loads(req)['errmsg']
                    self.Ui.textEdit_log.append(self.getTime()+str(error2))
                    break
        except Exception as e:
            self.Ui.textEdit_log.append(self.getTime()+str(e))
            self.Ui.textEdit_log.append(self.getTime() + "查询结束！")
            self.Ui.action_start.setEnabled(True)
            self.Ui.pushButton_start.setEnabled(True)

            # print(data)

        self.Ui.textEdit_log.append(self.getTime() + "查询结束！")
        self.Ui.action_start.setEnabled(True)
        self.Ui.pushButton_start.setEnabled(True)
    def Shodan_start(self,text,page):
        try:
            data = ''
            self.Ui.action_start.setEnabled(False)
            self.Ui.pushButton_start.setEnabled(False)
            api = Shodan(self.shodan_key)
            self.Ui.textEdit_log.append(self.getTime()+'正在查询数据，请稍等...')
            eventlet.monkey_patch(thread=False)
            try:
                timeout = int(self.Ui.comboBox_timeout.currentText())
                with eventlet.Timeout(timeout, True):
                    search = api.search(text, int(page))
            except:
                self.Ui.textEdit_log.append(self.getTime() + '获取数据超时')
                self.Ui.action_start.setEnabled(True)
                self.Ui.pushButton_start.setEnabled(True)
                return

            for result in search['matches']:
                # print(result)
                ip = result['ip_str'].strip()
                port = result['port']
                data +=  'http://'+str(ip)+':'+str(port)+'\n'
            self.Ui.textEdit_result.append(data.strip())
            self.Ui.textEdit_log.append(self.getTime() + "查询结束！")
        except Exception as e:
            self.Ui.textEdit_log.append(self.getTime() + str(e))
            self.Ui.action_start.setEnabled(True)
            self.Ui.pushButton_start.setEnabled(True)
        self.Ui.action_start.setEnabled(True)
        self.Ui.pushButton_start.setEnabled(True)
    def Censys_start(self,text,all_page):
        try:
            self.Ui.action_start.setEnabled(False)
            self.Ui.pushButton_start.setEnabled(False)
            for page in range(all_page):
                try:
                    page=page+1
                    self.Ui.textEdit_log.append(self.getTime() + '开始查询第%s页...' % page)
                    API_URL = "https://www.censys.io/api/v1/search/ipv4"
                    data = {
                        "query": text,
                        "page": page,
                        "fields": ["ip"],
                    }
                    timeout = int(self.Ui.comboBox_timeout.currentText())
                    res = requests.post(API_URL, data=json.dumps(data), auth=(self.censys_API_ID, self.censys_Secret),timeout=timeout)
                    results = res.json()
                    data = ''
                    self.Ui.textEdit_log.append(self.getTime() + "共获取到%s条数据" % len(results["results"]))
                    for result in results["results"]:
                        data+= result["ip"] + "\n"
                    self.result_adddata(data.strip())
                    if len(results["results"])<100:
                        break
                except Exception as e:
                    self.Ui.textEdit_log.append(self.getTime() + str(e))
                    self.Ui.action_start.setEnabled(True)
                    self.Ui.pushButton_start.setEnabled(True)
                    break
        except Exception as e:
            self.Ui.textEdit_log.append(self.getTime()+str(e))
            self.Ui.action_start.setEnabled(True)
            self.Ui.pushButton_start.setEnabled(True)

        self.Ui.textEdit_log.append(self.getTime() + "查询结束！")
        self.Ui.action_start.setEnabled(True)
        self.Ui.pushButton_start.setEnabled(True)
    def ZoomEye_start(self,text,all_page):
        self.Ui.action_start.setEnabled(False)
        self.Ui.pushButton_start.setEnabled(False)
        if self.zoomeye_access_token=="":
            self.Ui.textEdit_log.append(self.getTime() + "正在登陆...")
            result = self.ZoomEye_login()
            if result:
                self.ZoonmEye_search(text,all_page)
        else:
            self.ZoonmEye_search(text,all_page)
        self.Ui.textEdit_log.append(self.getTime() + "查询结束！")
        self.Ui.action_start.setEnabled(True)
        self.Ui.pushButton_start.setEnabled(True)
    def ZoonmEye_search(self,text,all_page):
        headers2 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
            'Authorization': 'JWT ' + self.zoomeye_access_token,
        }
        for page in range(all_page):
            data = ''
            page = page + 1
            self.Ui.textEdit_log.append(self.getTime() + '开始查询第%s页...' % page)
            # try:
            url = 'https://api.zoomeye.org/host/search?query={}&facet=app,os&page='.format(text)
            timeout = int(self.Ui.comboBox_timeout.currentText())
            r = requests.get(url=url + str(page), headers=headers2,timeout=timeout)
            # print(r.text)
            r_decoded = json.loads(r.text)
            try:
                self.Ui.textEdit_log.append(self.getTime() + "共获取到%s条数据" % len(r_decoded['matches']))
                for x in r_decoded['matches']:
                    # print(x)
                    data += 'http://' + x['ip']+":"+str(x['portinfo']['port'])+'\n'
                    # print(x['portinfo']['port'])
                self.result_adddata(data.strip())
                if len(r_decoded) < 20:
                    break
            except:
                # print(r_decoded['message'])
                self.Ui.textEdit_log.append(self.getTime() + str(r_decoded['message']))
                self.Ui.action_start.setEnabled(True)
                self.Ui.pushButton_start.setEnabled(True)


    def ZoomEye_login(self):
        data = {
            'username': self.zoomeye_username,
            'password': self.zoomeye_password
        }
        data_encoded = json.dumps(data)  # dumps 将 python 对象转换成 json 字符串
        try:
            r = requests.post(url='https://api.zoomeye.org/user/login', data=data_encoded,timeout=5)
            r_decoded = json.loads(r.text)  # loads() 将 json 字符串转换成 python 对象
            # print(r_decoded)
            self.zoomeye_access_token = r_decoded['access_token']
            self.Ui.textEdit_log.append(self.getTime() + '登陆成功！')
            return  self.zoomeye_access_token
        except Exception as e:
            # print(str(e))
            self.Ui.textEdit_log.append(self.getTime()+str(e))
            return False
    #自动增加HTTP头
    def result_adddata(self,data):
        if self.Ui.checkBox_addhttp.isChecked():
            if data[0:4] !="http":
                data = "http://"+data
            data2  = data.replace('\nhttp','~')
            data2 =data2.replace('\n','\nhttp://')
            data2 = data2.replace('~','\nhttp')
            self.Ui.textEdit_result.append(data2)
        else:
            self.Ui.textEdit_result.append(data)

    def save_result(self):
        data = self.Ui.textEdit_result.toPlainText()
        if data != '':
            filename = self.file_save("result.txt")
            if filename != "" and filename:
                f = open(filename,'w',encoding='utf-8')
                f.write(data)
                f.close()
        else:
            self.Ui.textEdit_log.append(self.getTime()+'没有结果可以保存！')
    def clear(self):
        self.Ui.textEdit_result.clear()
        self.Ui.textEdit_log.clear()
    def file_config(self):
        # 实例化configParser对象
        config = configparser.ConfigParser()
        # -read读取ini文件
        config.read('config.ini', encoding='utf-8')
        try:
            if 'Shodan' not in config:  # 如果分组type不存在则插入type分组
                config.add_section('Shodan')
                config.set("Shodan", "key", 'X')
                config.write(open('config.ini', "r+", encoding="utf-8"))  # r+模式
            else:
                self.shodan_key = config.get('Shodan', 'key')
            if 'Censys' not in config:  # 如果分组type不存在则插入type分组
                config.add_section('Censys')
                config.set("Censys", "API_ID", 'X')
                config.set("Censys", "Secret", 'X')
                config.set("Censys", "api", 'X')
                config.write(open('config.ini', "r+", encoding="utf-8"))  # r+模式
            else:
                self.censys_API_ID = config.get('Censys', 'API_ID')
                self.censys_Secret = config.get('Censys', 'Secret')
            if 'FOFA' not in config:  # 如果分组type不存在则插入type分组
                config.add_section('FOFA')
                config.set("FOFA", "email", 'X')
                config.set("FOFA", "key", 'X')
                config.set("FOFA", "api", 'X')
                config.write(open('config.ini', "r+", encoding="utf-8"))  # r+模式
            else:
                self.fofa_email = config.get('FOFA', 'email')
                self.fofa_key = config.get('FOFA', 'key')
                self.fofa_api = config.get('FOFA', 'api')
                config.write(open('config.ini', "r+", encoding="utf-8"))  # r+模式
            if 'ZoomEye' not in config:  # 如果分组type不存在则插入type分组
                config.add_section('ZoomEye')
                config.set("ZoomEye", "username", 'X')
                config.set("ZoomEye", "password", 'X')
                config.write(open('config.ini', "r+", encoding="utf-8"))  # r+模式
            else:
                self.zoomeye_username = config.get('ZoomEye', 'username')
                self.zoomeye_password = config.get('ZoomEye', 'password')
        except Exception as  e:
            self.Ui.action_start.setEnabled(True)
            self.Ui.pushButton_start.setEnabled(True)
            self.Ui.textEdit_log.append(self.getTime()+str(e))
            pass

    def getTime(self):
        now = datetime.now()
        return now.strftime('[%H:%M:%S]')
    def open_key_settings(self):
        self.key_settings = Ui_Form()
        self.dialog = QtWidgets.QDialog(self)
        self.key_settings.setupUi(self.dialog)
        self.dialog.setFixedSize(self.dialog.width(), self.dialog.height())
        self.key_settings.lineEdit_shodan_key.setText(self.shodan_key)
        self.key_settings.lineEdit_censys_API_ID.setText(self.censys_API_ID)
        self.key_settings.lineEdit_censys_Secret.setText(self.censys_Secret)
        self.key_settings.lineEdit_fofa_email.setText(self.fofa_email)
        self.key_settings.lineEdit_fofa_key.setText(self.fofa_key)
        self.key_settings.lineEdit_zoomeye_username.setText(self.zoomeye_username)
        self.key_settings.lineEdit_zoomeye_password.setText(self.zoomeye_password)
        self.key_settings.pushButton_save.clicked.connect(self.save_key_config)
        self.key_settings.pushButton_close.clicked.connect(lambda:self.dialog.close())
        self.dialog.show()
    def save_key_config(self):
        self.shodan_key = self.key_settings.lineEdit_shodan_key.text()
        self.censys_API_ID = self.key_settings.lineEdit_censys_API_ID.text()
        self.censys_Secret = self.key_settings.lineEdit_censys_Secret.text()
        self.fofa_email = self.key_settings.lineEdit_fofa_email.text()
        self.fofa_key = self.key_settings.lineEdit_fofa_key.text()
        self.zoomeye_username = self.key_settings.lineEdit_zoomeye_username.text()
        self.zoomeye_password = self.key_settings.lineEdit_zoomeye_password.text()
        # 实例化configParser对象
        config = configparser.ConfigParser()
        # -read读取ini文件
        config.read('config.ini', encoding='utf-8')
        # 往section添加key和value
        if self.zoomeye_username!='' and self.zoomeye_password!='':
            config.set("ZoomEye", "username", self.zoomeye_username)
            config.set("ZoomEye", "password", self.zoomeye_password)
        if self.shodan_key!='' :
            config.set("Shodan", "key", self.shodan_key)
        if self.fofa_email != '' and self.fofa_key != '':
            config.set("FOFA", "email", self.fofa_email)
            config.set("FOFA", "key", self.fofa_key)
        if self.censys_API_ID!='' :
            config.set("Censys", "API_ID", self.censys_API_ID)
            config.set("Censys", "Secret", self.censys_Secret)
        config.write(open('config.ini', "w", encoding="utf-8"))  # r+模式
        self.dialog.close()
    def file_save(self, filename):
        fileName, filetype = QFileDialog.getSaveFileName(self, (r"保存文件"), (filename),r"All files(*.*)")
        return fileName
    # 更新
    def version_update(self):
        webbrowser.open("https://github.com/qianxiao996/Get_vuln_targets/")

    # 关于
    def about(self):
        box = QtWidgets.QMessageBox()
        box.setIcon(1)
        box.about(self, "About",
                  "\t\t\tAbout\n       此程序为一款URL采集工具，支持FOFA、Shodan、Censys、ZoomEye！\n\t\t\t   Powered by qianxiao996")
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindows()
    window.show()
    sys.exit(app.exec_())