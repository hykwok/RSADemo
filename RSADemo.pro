QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# if use DEPRECATED OpenSSL 1.x.x library, set the following value to 1
USE_DEPRECATED_OPENSSL_LIB = 0

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    rsaprocess.cpp

HEADERS += \
    mainwindow.h \
    rsaprocess.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32 {

isEqual(USE_DEPRECATED_OPENSSL_LIB, 1) {
message("Use DEPRECATED OpenSSL 1.X.X")
LIBS += -L$$PWD/'../../../../../Program Files/OpenSSL-Win64/lib/' -llibcrypto
} else {
message("Use OpenSSL 3.X.X")
LIBS += -L$$PWD/'../../../../../Program Files/OpenSSL-Win64/lib/VC/x64/MD' -llibcrypto
}

INCLUDEPATH += $$PWD/'../../../../../Program Files/OpenSSL-Win64/include'
DEPENDPATH += $$PWD/'../../../../../Program Files/OpenSSL-Win64/include'

}

unix {

CONFIG += link_pkgconfig
PKGCONFIG += libcrypto

}
