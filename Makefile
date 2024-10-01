jre := $(shell readlink $(shell which java))
fatjar = app/build/libs/app.jar
sources := $(shell find app/src -type f)

$(fatjar): $(sources)
	gradle jar

package: $(fatjar)

run: $(fatjar)
	java -jar $<

clean:
	gradle clean

deploy: package
	scp -r $(fatjar) pi@strawberry:~/ || scp -r $(fatjar) pi@192.168.0.60:~/
	scp -r $(fatjar) pi@cranberry:~/ || scp -r $(fatjar) pi@192.168.0.61:~/

capabilities_set:
	sudo setcap cap_net_raw,cap_net_admin=eip $(jre)

capabilities_get:
	sudo getcap $(jre)

capabilities_unset:
	sudo setcap -r $(jre)
