# WPICTF 2020
`PaperPlaneJr` `151 pts` `384th`

> 2020/04/18 05:00 - 2020/04/20 05:00  
> https://ctf.wpictf.xyz  
> 31.04


## Writeup

### dorsia2
`web` `50 pts` `WPI{1_H4VE_2_return_SOME_VIDE0TAP3S}`

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The second card.
> 
> http://dorsia2.wpictf.xyz:31337/index.html or 31338 or 31339
> 
> made by: awg
> 
> Hint: flag in ~/flag.txt

The first link is an video.
According to the statement, the code is on the second card, which is

```cpp
/home/ctf/web/
--------------
#include <stdio.h>
#include <unistd.h>


int main() {
    char a[69] = {0};

    scanf("GET /%s", a);
    printf("HTTP 200\r\n\r\n");
    fflush(stdout);

    execlp("cat", a, a, 0);

    return 0;
}
```

We can find that the code will return the content of the file
    we passed by the GET method.
The hint said that the `flag` is at `~/flag.txt`,
    which is `/home/ctf/flag.txt`.

Query `http://dorsia2.wpictf.xyz:31337//home/web/flag.txt` and get the flag.

### Can you Read?
`misc` `1 pts` `WPI{Yes_I_c4N_R3ad}`

> WPI{Yes_I_c4N_R3ad}

### autograder
`web` `100` `WPI{D0nt_run_as_r00t}`

> A prof made a little homework grader at https://autograder.wpictf.xyz/ but I heard he is hiding a flag at /home/ctf/flag.txt
> 
> made by: awg and rm -k

At first, we try to open the `/home/ctf/flag.txt` directly with `fopen` and failed.

Then we think that the error messages usually have some information.

We try to make some errors and find that the error messages will be respond.

We try to include the `/home/ctf/flag.txt` and find the key in error message.


## Unsolved

### LynxVE
`linux` `50 pts`

[Writeup](http://taqini.space/2020/04/20/WPICTF-2020-pwn-linux-wp/#Linux)
> Type G and input URL=file:/// to visit local files

> ssh ctf@lynxve.wpictf.xyz
> 
> pass: lynxVE
> 
> made by: acurless

Default login shell is `lynx`.

### dorsia1
`pwn` `100 pts`

[Writeup](https://github.com/C-Brown/CTFs/blob/master/WPICTF2020/pwn/dorsia1.md)
> Padding 69 bytes, and the `system` is magic function.

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The first card.
> 
> nc dorsia1.wpictf.xyz 31337 or 31338 or 31339
> 
> made by: awg
> 
> Hint: Same libc as dorsia4, but you shouldn't need the file to solve.

We think that this is a BOF.

We send `//bin/sh\0...<system_plt>` as payload
    because the `rdi` will be used as the parameter of `system()`.

However, it crash after the `system()` been called.

### Suckmore Shell 2.0
`linux` `200 pts`

[Writeup](https://github.com/jdesalle/WriteUps/blob/master/WPICTF2020/Linux/Suckmore%20Shell%202.0.md)
> `$ more flag.txt`

> After its abysmal performance at WPICTF 2019, suckmore shell v1 has been replaced with a more secure, innovative and performant version, aptly named suckmore shell V2.
> 
> ssh smsh@smsh.wpictf.xyz pass: suckmore>suckless
> 
> made by: acurless

`redirect (>)` and `pipe (|)` are blocked.

`$ cat flag.txt` will be run as `$ cat`.

Maybe some keyword are blockde, like `flag`.

Variables can not be used, either.
