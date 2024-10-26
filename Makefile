jre := $(shell readlink $(shell which java))
fatjarPep = pep/build/libs/pep.jar
sourcesCommon := $(shell find common/src -type f)
sourcesPdp := $(shell find pdp/src -type f)
sourcesPep := $(shell find pep/src -type f)

$(fatjarPep): $(sourcesPdp) $(sourcesPep) $(sourcesCommon)
	gradle jar

package: $(fatjarPep)

run: $(fatjarPep)
	java -jar $<

clean:
	gradle clean

deploy: package
	scp -r $(fatjarPep) pi@strawberry:~/ || scp -r $(fatjarPep) pi@192.168.0.60:~/
	scp -r $(fatjarPep) pi@cranberry:~/ || scp -r $(fatjarPep) pi@192.168.0.61:~/

capabilities_set:
	sudo setcap cap_net_raw,cap_net_admin=eip $(jre)

capabilities_get:
	sudo getcap $(jre)

capabilities_unset:
	sudo setcap -r $(jre)
