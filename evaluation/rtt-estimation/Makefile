ip_passive = 192.168.0.61
ip_active = 192.168.0.60
host_passive = pi@$(ip_passive)
host_active = pi@$(ip_active)
port = 8000
readings = 10000

sources_local = ./
sources = ~/rtt-estimation

executable_passive = python $(sources)/PassiveEntity.py $(port)
executable_active = python $(sources)/ActiveEntity.py $(ip_passive) $(port) $(readings) 
process = rtt-estimation

copy:
	ssh $(host_passive) "mkdir -p $(sources)"
	scp -r $(sources_local) $(host_passive):$(sources)
	ssh $(host_active) "mkdir -p $(sources)"
	scp -r $(sources_local) $(host_active):$(sources)

clean:
	ssh $(host_passive) "rm -r $(sources)"
	ssh $(host_active) "rm -r $(sources)"

run:
	ssh $(host_passive) "$(executable_passive) &> /dev/null &"
	-ssh $(host_active) "$(executable_active) tmp"
	-scp $(host_active):~/tmp.json ./
	-ssh $(host_passive) "pkill -f PassiveEntity.py"
