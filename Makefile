#******************** VARIABLES ********************#

#---------- NAMES ----------#

NAME		=		ft_ssl_md5
LIB_NAME	=		libft

#---------- DIRECTORIES ----------#

SRC_DIR		=		src/
LIB_DIR		=		lib/
INC_DIR		=		include/
BUILD_DIR	=		.build/

#---------- SOURCES ----------#

SRC_FILES	=		main.c		\
					hash/md5.c	\

#---------- LIBRARIES ----------#

LIBFT		=		$(LIB)$(LIB_NAME).a

#---------- BUILD ----------#

SRC			=		$(addprefix $(SRC_DIR), $(SRC_FILES))
OBJ			=		$(addprefix $(BUILD_DIR), $(SRC:.c=.o))
LIB			=		$(addprefix $(LIB_DIR), $(LIB_NAME))
DEPS		=		$(addprefix $(BUILD_DIR), $(SRC:.c=.d))

#---------- COMPILATION ----------#

C_FLAGS		=		-Wall -Werror -Wextra

I_FLAGS		=		-I$(INC_DIR) -I$(LIB_DIR)$(LIB_NAME)/include/

L_FLAGS		=		-L$(LIB) -lft

D_FLAGS		=		-MMD -MP

#---------- COMMANDS ----------#

RM			=		rm -rf
MKDIR		=		mkdir -p

#******************** RULES ********************#

#---------- GENERAL ----------#

.PHONY:				all
all:				$(NAME)

.PHONY:				clean
clean:
					$(RM) $(BUILD_DIR)

.PHONY:				fclean
fclean:				clean
					$(RM) $(NAME) $(TEST) $(TEST_BONUS)

.PHONY:				re
re:					fclean
					$(MAKE)

#---------- RUN ----------#

.PHONY:				run
run:				$(TEST)
					./$(TEST)

.PHONY:				leak
leak:				$(TEST)
					valgrind --leak-check=full ./$(TEST)

#---------- EXECUTABLES ----------#

-include			$(DEPS)

$(NAME):			$(LIBFT) $(OBJ)
					$(CC) $(OBJ) $(L_FLAGS) -o $@

#---------- OBJECTS FILES ----------#

$(BUILD_DIR)%.o:	%.c
					$(MKDIR) $(shell dirname $@)
					$(CC) $(C_FLAGS) $(D_FLAGS) $(I_FLAGS) -c $< -o $@

#---------- LIBRARIES ----------#

$(LIBFT):			FORCE
					$(MAKE) -C $(LIB)

.PHONY:				FORCE
FORCE:
