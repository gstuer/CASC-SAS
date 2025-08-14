###
# Common
###
jre := $(shell readlink $(shell which java))
fatjarPep = pep/build/libs/pep.jar
fatjarPdp = pdp/build/libs/pdp.jar
sourcesCommon := $(shell find common/src -type f)
sourcesPdp := $(shell find pdp/src -type f)
sourcesPep := $(shell find pep/src -type f)

$(fatjarPep): $(sourcesPep) $(sourcesCommon)
	gradle jar

$(fatjarPdp): $(sourcesPdp) $(sourcesCommon)
	gradle jar

package: $(fatjarPep) $(fatjarPdp)

run: $(fatjarPep)
	java -jar $<

clean:
	gradle clean

deploy: package
	scp -r $(fatjarPep) pi@192.168.0.60:~/
	scp -r $(fatjarPep) pi@192.168.0.61:~/
	scp -r $(fatjarPdp) pi@192.168.0.64:~/

capabilities_set:
	sudo setcap cap_net_raw,cap_net_admin=eip $(jre)

capabilities_get:
	sudo getcap $(jre)

capabilities_unset:
	sudo setcap -r $(jre)

###
# Performance Analysis
###
ip_passive = 192.168.0.63
ip_active = 192.168.0.62
ip_pep_passive = 192.168.0.61
ip_pep_active = 192.168.0.60
ip_pdp = 192.168.0.64

host_passive = pi@$(ip_passive)
host_active = pi@$(ip_active)
host_pep_passive = pi@$(ip_pep_passive)
host_pep_active = pi@$(ip_pep_active)
host_pdp = pi@$(ip_pdp)

port = 8000
readings = 5000
readings_dryrun = 1000

rtt_sources_local = ./evaluation/rtt-estimation
rtt_sources = ~/rtt-estimation

rtt_executable_passive = python $(rtt_sources)/PassiveEntity.py $(port)
rtt_executable_active = python $(rtt_sources)/ActiveEntity.py $(ip_passive) $(port) $(readings)
rtt_executable_active_dryrun = python $(rtt_sources)/ActiveEntity.py $(ip_passive) $(port) $(readings_dryrun)

performance_analysis_deploy: package
	scp -r $(fatjarPep) $(host_pep_passive):~/
	scp -r $(fatjarPep) $(host_pep_active):~/
	scp -r $(fatjarPdp) $(host_pdp):~/

	ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 -f &> /dev/null &"
	ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 -f &> /dev/null &"

	scp -r $(rtt_sources_local) $(host_passive):$(rtt_sources)
	scp -r $(rtt_sources_local) $(host_active):$(rtt_sources)

	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_run: performance_analysis_deploy
	$(MAKE) performance_analysis_run_unauthorized
	$(MAKE) performance_analysis_run_unauthenticated
	$(MAKE) performance_analysis_run_hmacsha512
	$(MAKE) performance_analysis_run_rsa
	$(MAKE) performance_analysis_run_ed25519

performance_analysis_run_unauthorized:
	-ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto NoOperation -f &> /dev/null &"
	-ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto NoOperation -f &> /dev/null &"

	-ssh $(host_passive) "$(rtt_executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) Unauthorized"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) Unauthorized"
	-ssh $(host_active) "$(rtt_executable_active) Unauthorized"
	-scp $(host_active):~/Unauthorized.json ./

	-ssh $(host_passive) "pkill -f PassiveEntity.py"
	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_run_unauthenticated:
	-ssh $(host_pdp) "java -jar pdp.jar --authentication localhost --crypto NoOperation &> /dev/null &"
	-ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto NoOperation &> /dev/null &"
	-ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto NoOperation &> /dev/null &"

	-ssh $(host_passive) "$(rtt_executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) NoOperation"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) NoOperation"
	-ssh $(host_active) "$(rtt_executable_active) NoOperation"
	-scp $(host_active):~/NoOperation.json ./

	-ssh $(host_passive) "pkill -f PassiveEntity.py"
	-ssh $(host_pdp) "pkill -f pdp.jar"
	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_run_hmacsha512:
	-ssh $(host_pdp) "java -jar pdp.jar --authentication localhost --crypto HmacSHA512/256 &> /dev/null &"
	-ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 &> /dev/null &"
	-ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 &> /dev/null &"

	-ssh $(host_passive) "$(rtt_executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) HmacSHA512_256"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) HmacSHA512_256"
	-ssh $(host_active) "$(rtt_executable_active) HmacSHA512_256"
	-scp $(host_active):~/HmacSHA512_256.json ./

	-ssh $(host_passive) "pkill -f PassiveEntity.py"
	-ssh $(host_pdp) "pkill -f pdp.jar"
	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_run_rsa:
	-ssh $(host_pdp) "java -jar pdp.jar --authentication localhost --crypto SHA512withRSA &> /dev/null &"
	-ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto SHA512withRSA &> /dev/null &"
	-ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto SHA512withRSA &> /dev/null &"

	-ssh $(host_passive) "$(rtt_executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) SHA512withRSA"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) SHA512withRSA"
	-ssh $(host_active) "$(rtt_executable_active) SHA512withRSA"
	-scp $(host_active):~/SHA512withRSA.json ./

	-ssh $(host_passive) "pkill -f PassiveEntity.py"
	-ssh $(host_pdp) "pkill -f pdp.jar"
	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_run_ed25519:
	-ssh $(host_pdp) "java -jar pdp.jar --authentication localhost --crypto Ed25519 &> /dev/null &"
	-ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto Ed25519 &> /dev/null &"
	-ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto Ed25519 &> /dev/null &"

	-ssh $(host_passive) "$(rtt_executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) Ed25519"
	-ssh $(host_active) "$(rtt_executable_active_dryrun) Ed25519"
	-ssh $(host_active) "$(rtt_executable_active) Ed25519"
	-scp $(host_active):~/Ed25519.json ./

	-ssh $(host_passive) "pkill -f PassiveEntity.py"
	-ssh $(host_pdp) "pkill -f pdp.jar"
	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"

performance_analysis_clean:
	ssh $(host_pep_passive) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 -f &> /dev/null &"
	ssh $(host_pep_active) "java -jar pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 --authentication localhost --crypto HmacSHA512/256 -f &> /dev/null &"

	ssh $(host_passive) "rm -rf $(rtt_sources)"
	ssh $(host_active) "rm -rf $(rtt_sources)"

	-ssh $(host_pep_passive) "pkill -f pep.jar"
	-ssh $(host_pep_active) "pkill -f pep.jar"
