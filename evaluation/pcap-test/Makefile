sources_dir = src
sources = $(wildcard $(sources_dir)/*.cpp)
binary_dir = out
binary = core
optimization_default = 0
compiler = g++
flags = -lpcap -std=c++23 -O$(optimization_default) -Wall

compile: $(binary_dir)/$(binary)

$(binary_dir):
	mkdir $(binary_dir)

$(binary_dir)/$(binary): $(sources) $(binary_dir)
	$(compiler) $(flags) -o $(binary_dir)/$(binary) $(sources)

clean:
	rm -rf $(binary_dir)

run: $(binary_dir)/$(binary)
	sudo ./$<
