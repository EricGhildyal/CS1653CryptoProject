import os
os.system("javac -classpath .:bcprov-jdk15on-158.jar:commons-codec-1.11.jar:org.json.jar *.java")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar:commons-codec-1.11.jar:org.json.jar RunGroupServer authdb.txt'")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar:commons-codec-1.11.jar:org.json.jar RunFileServer'")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar:commons-codec-1.11.jar:org.json.jar RunClient'")
