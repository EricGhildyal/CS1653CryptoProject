import os
os.system("javac -classpath .:bcprov-jdk15on-158.jar *.java")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar RunGroupServer'")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar RunFileServer'")
os.system("gnome-terminal -e 'java -classpath .:bcprov-jdk15on-158.jar RunClient'")

