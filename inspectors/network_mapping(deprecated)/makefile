ISNORT := /opt/snort/include/snort
SNORT := /opt/snort/bin/snort
OUTPUTDIR := p
MAKEDIR := .m

MODULE = network_mapping.so
MODULE = network_mapping_debug.so
RELEASE_MODULE = network_mapping.so

CC_SOURCES = \
	inspector.cc \
	lioli.cc
	
CC_HEADERS = \
	lioli.h

OBJS=$(addprefix $(MAKEDIR)/, $(subst .cc,.o,$(CC_SOURCES)))
DEPS=$(addprefix $(MAKEDIR)/, $(subst .cc,.d,$(CC_SOURCES)))

.PHONY: test test-data clean format build oldstyle gdb
test: $(OUTPUTDIR)/$(MODULE)
	sh3 -sanitize none -t $(OUTPUTDIR)/$(MODULE) $(TEST_LIMIT)

test-data: $(OUTPUTDIR)/$(MODULE)
	$(SNORT) -v -c ../../test_config/cfg.lua --plugin-path $(OUTPUTDIR) --pcap-dir ../../test_data --warn-all

test-local: $(OUTPUTDIR)/$(MODULE)
	$(SNORT) -v -c tests/test-local.lua --plugin-path $(OUTPUTDIR) --pcap-dir pcaps --warn-all

$(MAKEDIR):
	mkdir $(MAKEDIR)

$(OUTPUTDIR):
	mkdir $(OUTPUTDIR)

clean:
	if [ -f $(OUTPUTDIR)/$(MODULE) ]; then rm $(OUTPUTDIR)/$(MODULE); fi
	if [ -f $(OUTPUTDIR)/$(RELEASE_MODULE) ]; then rm $(OUTPUTDIR)/$(RELEASE_MODULE); fi
	if [ -d $(MAKEDIR) ]; then rm -r $(MAKEDIR); fi
	@echo "\e[3;32mClean done\e[0m"

format:
	clang-format -i $(CC_SOURCES) $(CC_HEADERS)

build: $(OUTPUTDIR)/$(MODULE)
	@echo "\e[3;32mBuild done\e[0m"

release:
	@echo "\e[3;37mMaking release - this might take a while...\e[0m"
	g++ -O3 -std=c++2b -fPIC -Wall -Wextra -fsanitize=undefined -shared -I $(ISNORT) $(CC_SOURCES) -o $(OUTPUTDIR)/$(RELEASE_MODULE)
	@echo "\e[3;32mRelease build done\e[0m"

gdb: $(OUTPUTDIR)/$(MODULE)
	@echo "\e[3;37mStarting debugger...\e[0m"
	gdb --args $(SNORT) -v -c tests/test-local.lua --plugin-path $(OUTPUTDIR) --pcap-dir pcaps --warn-all

-include ${DEPS}

$(MAKEDIR)/%.o : %.cc | $(MAKEDIR)
	g++ -MMD -MT '$(patsubst %.cc,$(MAKEDIR)/%.o,$<)' -pipe -O0 -std=c++2b -fPIC -Wall -Wextra -g -I $(ISNORT) -c $< -o $@

$(OUTPUTDIR)/$(MODULE): $(OBJS) | $(OUTPUTDIR)
	@echo "\e[3;37mLinking...\e[0m"
	g++ $(OBJS) -fPIC -shared -O0 -Wall -g -Wextra -o $@

