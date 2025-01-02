INC_DIR := include
SRC_DIR := source
BUILD_DIR := build

# Source and header files
SRCS := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
HEADERS := $(wildcard $(INC_DIR)/*.h) $(wildcard $(INC_DIR)/*/*.h)

# Object files
OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Compiler and flags
CC := clang

CFLAGS := -Wall -Wextra -Werror -pedantic -O0 -I$(INC) \
          -Waddress -Warray-bounds -Wcast-align -Wconversion \
          -Wfloat-equal -Wformat -Wimplicit-function-declaration \
          -Wmissing-prototypes -Wnull-dereference -Wshadow \
          -Wsign-compare -Wstrict-aliasing -Wuninitialized \
          -Wunused-variable 

# Target
all: $(OBJS)

# Rule to build object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c 
	@mkdir -p $(@D)  # Ensure the directory exists
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_DIR)


# Clean up
clean:
	rm -rf $(BUILD_DIR)

CRUST := $(patsubst $(SRC_DIR)/%.c, $(SRC_DIR)/%.uncrustify, $(SRCS))
CRUST += $(patsubst $(INC_DIR)/%.h, $(INC_DIR)/%.uncrustify, $(HEADERS))

uncrustify: $(CRUST)
$(eval $(SRC_DIR)/%.uncrustify: $(SRC_DIR)/%.c; uncrustify -c .uncrustify.cfg -f $$< > $$@)
$(eval $(INC_DIR)/%.uncrustify: $(INC_DIR)/%.h; uncrustify -c .uncrustify.cfg -f $$< > $$@)

cppcheck:
	cppcheck --force -q  --check-level=exhaustive --enable=all $(SRCS) $(HEADERS) -I $(INC_DIR) --checkers-report=cppcheck_report.xml 

.PHONY: all clean uncrustify cppcheck
