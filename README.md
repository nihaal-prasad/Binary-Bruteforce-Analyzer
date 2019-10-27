# Binary Bruteforce Analyzer
This program will allow a reverse engineer to analyze a several lines of code by bruteforcing the input values to those lines of code, recording the output, and displaying the results on a graph. Please note that this is currently a work in progress, and it there may be lots of bugs at this point in time.

### Required
* radare2
* r2pipe (Can be installed using pip)
* matplotlib (Can be installed using pip)

### Example Use
Suppose you had the following c program and you wanted to analyze the function magic().
```
#include<stdio.h>
#include<stdlib.h>

int magic(int x) {
    return x*x;
}

int main() {
    int x = magic(3);
    printf("%d\n", x);
}
```
This is its object dump:
```
0000000000001135 <magic>:
    1135:	55                   	push   %rbp
    1136:	48 89 e5             	mov    %rsp,%rbp
    1139:	89 7d fc             	mov    %edi,-0x4(%rbp)
    113c:	8b 45 fc             	mov    -0x4(%rbp),%eax
    113f:	0f af 45 fc          	imul   -0x4(%rbp),%eax
    1143:	5d                   	pop    %rbp
    1144:	c3                   	retq   

0000000000001145 <main>:
    1145:	55                   	push   %rbp
    1146:	48 89 e5             	mov    %rsp,%rbp
    1149:	48 83 ec 10          	sub    $0x10,%rsp
    114d:	bf 03 00 00 00       	mov    $0x3,%edi
    1152:	e8 de ff ff ff       	callq  1135 <magic>
    1157:	89 45 fc             	mov    %eax,-0x4(%rbp)
    115a:	8b 45 fc             	mov    -0x4(%rbp),%eax
    115d:	89 c6                	mov    %eax,%esi
    115f:	48 8d 3d 9e 0e 00 00 	lea    0xe9e(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1166:	b8 00 00 00 00       	mov    $0x0,%eax
    116b:	e8 c0 fe ff ff       	callq  1030 <printf@plt>
    1170:	b8 00 00 00 00       	mov    $0x0,%eax
    1175:	c9                   	leaveq 
    1176:	c3                   	retq   
    1177:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    117e:	00 00
```
If you run the following command, a graph will appear, which will display all of the outputs for the magic() function when you use inputs in the range [0,100] (0 is inclusive, 100 is exclusive). In this example, there are two breakpoints: sym.magic and sym.main+21. At sym.magic, the input register (which is set to be rdi) is changed to be one of the input values in the specified range. At sym.main+21, eax is read as the output value, and the point (rdi, eax) is plotted onto the graph.
```
python bruteforce_analysis.py example sym.magic sym.main+21 rdi eax [0,100]
```
![Image of graph](https://i.postimg.cc/Mp7ysZ0R/Screenshot-from-2019-10-26-19-19-03.png)

Furthermore, there is also a list of points printed out in the output:
```
Points:
[(0, 0), (1, 1), (2, 4), (4, 16), (3, 9), (5, 25), (7, 49), (6, 36), (8, 64), (9, 81), (14, 196), (10, 100), (11, 121), (12, 144), (13, 169), (17, 289), (16, 256), (15, 225), (18, 324), (19, 361), (23, 529), (20, 400), (21, 441), (22, 484), (24, 576), (26, 676), (25, 625), (28, 784), (27, 729), (30, 900), (29, 841), (32, 1024), (31, 961), (33, 1089), (35, 1225), (36, 1296), (34, 1156), (37, 1369), (38, 1444), (41, 1681), (39, 1521), (40, 1600), (42, 1764), (43, 1849), (46, 2116), (44, 1936), (45, 2025), (47, 2209), (49, 2401), (50, 2500), (48, 2304), (51, 2601), (53, 2809), (54, 2916), (52, 2704), (55, 3025), (56, 3136), (57, 3249), (58, 3364), (60, 3600), (59, 3481), (61, 3721), (62, 3844), (64, 4096), (63, 3969), (65, 4225), (66, 4356), (71, 5041), (67, 4489), (68, 4624), (70, 4900), (69, 4761), (72, 5184), (76, 5776), (74, 5476), (75, 5625), (73, 5329), (80, 6400), (81, 6561), (78, 6084), (77, 5929), (79, 6241), (85, 7225), (83, 6889), (84, 7056), (86, 7396), (82, 6724), (88, 7744), (89, 7921), (87, 7569), (90, 8100), (91, 8281), (94, 8836), (93, 8649), (92, 8464), (96, 9216), (95, 9025), (97, 9409), (98, 9604), (99, 9801)]
```
