TEMPLATE = app
TARGET = 
DEPENDPATH  += . resources src
INCLUDEPATH += . src

# UI
FORMS     += src/passwordpromptdialog.ui
HEADERS   += src/passwordpromptdialog.h
SOURCES   += src/passwordpromptdialog.cpp

# BASE
HEADERS   += src/session.h
SOURCES   += src/main.c src/strings_en.c src/conversation.cpp
RESOURCES += resources/qsu.qrc

# DEPS
LIBS      += -lpam

