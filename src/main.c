#include "libft.h"
#include "md5.h"

int main(int argc, char **argv) {
	if (argc < 2) {
		ft_putstr_fd("No argument\n", STDERR_FILENO);
		return 1;
	}
	md5(argv[1]);
}