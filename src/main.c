#include "libft.h"
#include "md5.h"

int main(int argc, char **argv) {
	char *digest;
	if (argc < 2) {
		ft_putstr_fd("No argument\n", STDERR_FILENO);
	}
	digest = md5(argv[1]);
	ft_putstr_fd(digest, STDIN_FILENO);
}