# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'key_Settings.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(380, 424)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Form.sizePolicy().hasHeightForWidth())
        Form.setSizePolicy(sizePolicy)
        self.gridLayout_2 = QtWidgets.QGridLayout(Form)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.groupBox_3 = QtWidgets.QGroupBox(Form)
        self.groupBox_3.setMaximumSize(QtCore.QSize(16777215, 64))
        self.groupBox_3.setObjectName("groupBox_3")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.groupBox_3)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_5 = QtWidgets.QLabel(self.groupBox_3)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout.addWidget(self.label_5)
        self.lineEdit_shodan_key = QtWidgets.QLineEdit(self.groupBox_3)
        self.lineEdit_shodan_key.setObjectName("lineEdit_shodan_key")
        self.horizontalLayout.addWidget(self.lineEdit_shodan_key)
        self.verticalLayout_3.addLayout(self.horizontalLayout)
        self.gridLayout.addWidget(self.groupBox_3, 0, 0, 1, 1)
        self.groupBox = QtWidgets.QGroupBox(Form)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self.groupBox)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.label_2 = QtWidgets.QLabel(self.groupBox)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.horizontalLayout_7.addLayout(self.verticalLayout)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.lineEdit_fofa_email = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_fofa_email.setObjectName("lineEdit_fofa_email")
        self.verticalLayout_2.addWidget(self.lineEdit_fofa_email)
        self.lineEdit_fofa_key = QtWidgets.QLineEdit(self.groupBox)
        self.lineEdit_fofa_key.setObjectName("lineEdit_fofa_key")
        self.verticalLayout_2.addWidget(self.lineEdit_fofa_key)
        self.horizontalLayout_7.addLayout(self.verticalLayout_2)
        self.verticalLayout_8.addLayout(self.horizontalLayout_7)
        self.gridLayout.addWidget(self.groupBox, 1, 0, 1, 1)
        self.groupBox_5 = QtWidgets.QGroupBox(Form)
        self.groupBox_5.setObjectName("groupBox_5")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.groupBox_5)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.label_6 = QtWidgets.QLabel(self.groupBox_5)
        self.label_6.setObjectName("label_6")
        self.horizontalLayout_10.addWidget(self.label_6)
        self.lineEdit_censys_API_ID = QtWidgets.QLineEdit(self.groupBox_5)
        self.lineEdit_censys_API_ID.setObjectName("lineEdit_censys_API_ID")
        self.horizontalLayout_10.addWidget(self.lineEdit_censys_API_ID)
        self.verticalLayout_5.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        self.label_8 = QtWidgets.QLabel(self.groupBox_5)
        self.label_8.setObjectName("label_8")
        self.horizontalLayout_12.addWidget(self.label_8)
        self.lineEdit_censys_Secret = QtWidgets.QLineEdit(self.groupBox_5)
        self.lineEdit_censys_Secret.setObjectName("lineEdit_censys_Secret")
        self.horizontalLayout_12.addWidget(self.lineEdit_censys_Secret)
        self.verticalLayout_5.addLayout(self.horizontalLayout_12)
        self.verticalLayout_7.addLayout(self.verticalLayout_5)
        self.gridLayout.addWidget(self.groupBox_5, 2, 0, 1, 1)
        self.groupBox_2 = QtWidgets.QGroupBox(Form)
        self.groupBox_2.setObjectName("groupBox_2")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.groupBox_2)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_3 = QtWidgets.QLabel(self.groupBox_2)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_5.addWidget(self.label_3)
        self.lineEdit_zoomeye_username = QtWidgets.QLineEdit(self.groupBox_2)
        self.lineEdit_zoomeye_username.setObjectName("lineEdit_zoomeye_username")
        self.horizontalLayout_5.addWidget(self.lineEdit_zoomeye_username)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label_4 = QtWidgets.QLabel(self.groupBox_2)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_4.addWidget(self.label_4)
        self.lineEdit_zoomeye_password = QtWidgets.QLineEdit(self.groupBox_2)
        self.lineEdit_zoomeye_password.setObjectName("lineEdit_zoomeye_password")
        self.horizontalLayout_4.addWidget(self.lineEdit_zoomeye_password)
        self.verticalLayout_4.addLayout(self.horizontalLayout_4)
        self.verticalLayout_6.addLayout(self.verticalLayout_4)
        self.gridLayout.addWidget(self.groupBox_2, 3, 0, 1, 1)
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.pushButton_save = QtWidgets.QPushButton(Form)
        self.pushButton_save.setObjectName("pushButton_save")
        self.horizontalLayout_11.addWidget(self.pushButton_save)
        self.pushButton_close = QtWidgets.QPushButton(Form)
        self.pushButton_close.setObjectName("pushButton_close")
        self.horizontalLayout_11.addWidget(self.pushButton_close)
        self.gridLayout.addLayout(self.horizontalLayout_11, 4, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "KEY Settings"))
        self.groupBox_3.setTitle(_translate("Form", "Shodan"))
        self.label_5.setText(_translate("Form", "key"))
        self.groupBox.setTitle(_translate("Form", "FOFA"))
        self.label.setText(_translate("Form", "Email"))
        self.label_2.setText(_translate("Form", "key"))
        self.groupBox_5.setTitle(_translate("Form", "Censys"))
        self.label_6.setText(_translate("Form", "API ID"))
        self.label_8.setText(_translate("Form", "Secret"))
        self.groupBox_2.setTitle(_translate("Form", "ZoomEye"))
        self.label_3.setText(_translate("Form", "username"))
        self.label_4.setText(_translate("Form", "password"))
        self.pushButton_save.setText(_translate("Form", "保存"))
        self.pushButton_close.setText(_translate("Form", "关闭"))
