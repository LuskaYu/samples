SOURCE=source
PACKAGE=package
SCRIPT=script
MAKE=make
TMP_OUTPUT=local
LIBS=libs
APPS=apps
TAR_FILE=files.tar.gz
LIBS_LIST:=$(strip $(shell ls $(SOURCE)/$(LIBS)/))
APPS_LIST:=$(strip $(shell ls $(SOURCE)/$(APPS)/))
CUSTOM_LIST=$(LIBS) $(APPS) $(LIBS_LIST) $(APPS_LIST)
.PHONY: all clean install dist tmp_dir  $(CUSTOM_LIST) $(addsuffix, -clean, $(CUSTOM_LIST)) $(addsuffix, -install, $(CUSTOM_LIST)

all: apps
	@echo "make the whole project done"

apps: libs
	@for i in $(APPS_LIST);do $(MAKE) -w -C $(SOURCE)/$(APPS)/$$i ;done

libs:
	@for i in $(LIBS_LIST);do $(MAKE) -w -C $(SOURCE)/$(LIBS)/$$i;done

dist: install
	@tar -czvf $(TAR_FILE) $(TMP_OUTPUT) 1>/dev/null	

install: all tmp_dir
	@for i in $(APPS_LIST);do cp -rf $(SOURCE)/$(APPS)/$$i/$$i $(TMP_OUTPUT)/bin/; done
	
tmp_dir:
	@if [ ! -d $(TMP_OUTPUT) ];then mkdir -p $(TMP_OUTPUT)/bin/ ;fi

clean: apps-clean libs-clean
	@echo "clean the whole project done"
	@rm -rf $(TMP_OUTPUT)
	@rm -rf $(TAR_FILE)

apps-clean:
	@for i in $(APPS_LIST);do $(MAKE) -w -C $(SOURCE)/$(APPS)/$$i clean;done


libs-clean:
	@for i in $(LIBS_LIST);do $(MAKE) -w -C $(SOURCE)/$(LIBS)/$$i clean;done
