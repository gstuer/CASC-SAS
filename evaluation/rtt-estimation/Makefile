ip_passive = 192.168.0.50
ip_active = 192.168.0.51
host_passive = pi@$(ip_passive)
host_active = pi@$(ip_active)
port = 8000
readings = 10000

root = ~
sources_local = ./
sources = $(root)/rtt-estimation

executable_passive = python $(sources)/PassiveEntity.py $(port)
executable_active = python $(sources)/ActiveEntity.py $(ip_passive) $(port) $(readings)
output = $(sources)/output
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
	ssh $(host_passive) "exec -a $(process) $(executable_passive) --- &>> $(output) & disown"
	ssh $(host_active) "exec -a $(process) $(executable_active) --- &>> $(output)"

stop:
	-ssh $(host_passive) "pkill -f $(process)"
	-ssh $(host_active) "pkill -f $(process)"

status:
	-ssh $(host_passive) "cat $(output)"
	-ssh $(host_active) "cat $(output)"
