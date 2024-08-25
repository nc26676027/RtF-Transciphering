2

CKKS parameters: logN = 16, logSlots = 15, h = 192, logQP = 1546, levels = 25, scale= 2^40.000000, sigma = 3.200000, message scaling(log2) = 17.974415 

Generating bootstrapping keys...
Repeated free rotations:  [0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 3 5 6 7 9 10 11 12 13 14 15 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 33 56 62 63 66 84 124 132 959 960 990 991 1008 1023 1036 1064 1092 1952 1982 1983 2016 2044 2047 2072 2078 2100 3007 3024 3040 3052 3070 3071 3072 3080 3108 4031 4032 4062 4063 4095 5023 5024 5054 5055 5087 5118 5119 5120 6047 6078 6079 6111 6112 6142 6143 6144 7071 7102 7103 7135 7166 7167 7168 8095 8126 8127 8159 8190 8191 9149 9183 9184 9213 9215 9216 10173 10207 10208 10237 10239 10240 11197 11231 11232 11261 11263 11264 12221 12255 12256 12285 12287 12288 13214 13216 13246 13278 13279 13280 13310 13311 13312 14238 14240 14270 14302 14303 14304 14334 14335 15262 15264 15294 15326 15327 15328 15358 15359 15360 16286 16288 16318 16350 16351 16352 16382 16383 17311 17375 18335 18399 18432 19359 19423 20383 20447 20480 21405 21406 21437 21469 21470 21471 21501 21504 22429 22430 22461 22493 22494 22495 22525 22528 23453 23454 23485 23517 23518 23519 23549 24477 24478 24509 24541 24542 24543 24573 24576 25501 25565 25568 25600 26525 26589 26592 26624 27549 27613 27616 27648 28573 28637 28640 28672 29600 29632 29664 29696 30624 30656 30688 30720 31648 31680 31712 31743 31744 31774 32636 32640 32644 32672 32702 32704 32706 32735 32736 32737 32759 32760 32761 32762 32763 32764 32765 32766 32767 14336 384 1536 896 640 1280 1152 1664 1792 1920 1408 768 96 104 120 80 48 72 88 112 40 864 992 832 672 320 544 352 608 736 160 288 416 224 192 480 576 704 448 928 800 32752 32512 2560 3584]
image id:  0
plaintext data image0 = 
( 0.01584377885 ), 

( 0.016328401875000002 ), 
( 0.01923613995 ), 
( 0.019720762975 ), 
( 0.016813024875 ), 
( 0.0148745343 ), 
( 0.0177822709 ), 
( 0.016328401875000002 ), 
( 0.01584377885 ), 
( 0.016328401875000002 ), 
( 0.017297647899999997 ), 
( 0.016813024875 ), 
( 0.017297647899999997 ), 
( 0.019720762975 ), 
( 0.021174632025 ), 
( 0.02165925355 ), 
( 0.020205385975 ), 
( 0.0177822709 ), 
( 0.016813024875 ), 
( 0.016813024875 ), 
fullSlots, function
after HalfBoot: 

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.015823 0.016324 0.019236 0.019733 0.016805 0.014852 0.017784 ... -0.000016 -0.000004 0.000023 0.000039 0.000016 0.000012 0.000019 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.000008 0.000004 -0.000008 -0.000012 -0.000008 0.000023 0.000027 ... -0.000016 0.000023 0.000016 0.000004 0.000008 0.000004 0.000004 ]


Level: 8 (logQ = 380)
Scale: 2^40.000011
Level: 8
ValuesTest: [0.015823 0.016324 0.019236 0.019733 0.016805 0.014852 0.017784 ... -0.000000 0.000000 0.000000 -0.000000 0.000000 -0.000000 -0.000000 ]

Time transcipher : %v 2m53.093261724s
totalLevel 25 ResidualModuli:  10
LogSlots:  15
image id:  0
Importing parameters
Data imported successfully
image label: 3
Done generating Tensor
layer 0
ki: 1, hi: 32, wi: 32, ci: 3, ti: 3, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution

Level: 0 (logQ = 61)
Scale: 2^40.000046
Level: 0
ValuesTest: [-0.010606 -0.013150 -0.013131 -0.012461 -0.012426 -0.012786 -0.012534 ... -0.004100 -0.003957 -0.010093 -0.016273 -0.016266 -0.012758 -0.008827 ]

after BN

Level: 0 (logQ = 61)
Scale: 2^40.000046
Level: 0
ValuesTest: [-0.017873 -0.020417 -0.020398 -0.019728 -0.019693 -0.020054 -0.019801 ... 0.030543 0.030686 0.024550 0.018370 0.018377 0.021885 0.025815 ]

after btp real, stage:  0

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.017874 -0.020418 -0.020399 -0.019729 -0.019694 -0.020054 -0.019802 ... 0.030544 0.030687 0.024551 0.018370 0.018378 0.021885 0.025816 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.622146 -0.456210 -0.457364 -0.499214 -0.501481 -0.478627 -0.494558 ... 0.370728 0.377661 0.277804 0.588823 0.588338 0.374539 0.261062 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000002 -0.000003 -0.000003 -0.000001 -0.000001 -0.000002 -0.000001 ... 0.030543 0.030686 0.024550 0.018368 0.018375 0.021885 0.025813 ]

layer:  1
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  1

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.009612 0.017883 0.024268 0.028124 0.027295 0.024957 0.026520 ... 0.050232 0.047288 0.040797 0.036131 0.036848 0.030534 0.026074 ]

after BN layer:  1

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.016689 -0.008418 -0.002032 0.001823 0.000995 -0.001344 0.000219 ... -0.017908 -0.020852 -0.027343 -0.032009 -0.031292 -0.037606 -0.042066 ]

after BTS layer:  1

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.016699 -0.008423 -0.002034 0.001825 0.000995 -0.001344 0.000220 ... -0.017920 -0.020865 -0.027360 -0.032029 -0.031312 -0.037630 -0.042093 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.699407 -0.862113 -0.270796 0.243738 0.134146 -0.180637 0.029713 ... -0.619058 -0.429697 -0.268145 -0.449833 -0.409790 -0.786555 -0.915846 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000002 -0.000000 -0.000000 0.001823 0.000930 -0.000023 0.000138 ... -0.000002 -0.000003 -0.000001 -0.000004 -0.000002 -0.000001 -0.000005 ]

layer:  2
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  2

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.006194 -0.006278 -0.005785 -0.004149 -0.003524 -0.003880 -0.004024 ... 0.004054 0.002937 -0.000052 -0.000135 0.006358 0.005175 0.000766 ]

after BN layer:  2

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.003864 0.003779 0.004273 0.005909 0.006534 0.006178 0.006034 ... 0.001867 0.000750 -0.002239 -0.002322 0.004171 0.002988 -0.001421 ]

after cnnAddCipher layer:  2

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.003862 0.003777 0.004270 0.005907 0.006532 0.006176 0.006033 ... 0.032396 0.031421 0.022299 0.016037 0.022537 0.024862 0.024380 ]

after BTS layer:  2

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.003864 0.003779 0.004273 0.005911 0.006537 0.006180 0.006036 ... 0.032416 0.031441 0.022313 0.016047 0.022551 0.024878 0.024395 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.493570 0.483881 0.538745 0.698222 0.748765 0.720698 0.708830 ... 0.472606 0.416774 0.354029 0.740090 0.343357 0.271555 0.281238 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.003864 0.003779 0.004273 0.005911 0.006536 0.006179 0.006036 ... 0.032413 0.031438 0.022311 0.016045 0.022549 0.024877 0.024394 ]

layer:  3
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  3

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.021580 0.038592 0.039399 0.035650 0.032475 0.032720 0.032286 ... -0.006055 -0.008026 -0.002113 0.008116 0.011075 -0.002558 -0.008529 ]

after BN layer:  3

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.010281 0.027293 0.028100 0.024351 0.021176 0.021421 0.020986 ... -0.005616 -0.007586 -0.001673 0.008555 0.011515 -0.002118 -0.008089 ]

after BTS layer:  3

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.010287 0.027310 0.028117 0.024366 0.021190 0.021434 0.021000 ... -0.005619 -0.007591 -0.001674 0.008561 0.011522 -0.002120 -0.008095 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.913404 0.267451 0.282440 0.281913 0.411282 0.397915 0.421962 ... -0.672594 -0.819572 -0.224094 0.867976 0.914662 -0.281875 -0.846749 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.010287 0.027309 0.028116 0.024365 0.021188 0.021433 0.020998 ... -0.000000 -0.000001 -0.000004 0.008561 0.011521 -0.000000 -0.000001 ]

layer:  4
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  4

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.014722 -0.016135 -0.011388 -0.007733 -0.006622 -0.008145 -0.007857 ... 0.018215 0.019093 0.025243 0.024031 0.023018 0.020925 0.018851 ]

after BN layer:  4

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.016192 0.014778 0.019525 0.023180 0.024291 0.022768 0.023056 ... 0.016864 0.017742 0.023892 0.022680 0.021667 0.019574 0.017500 ]

after cnnAddCipher layer:  4

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.020054 0.018555 0.023796 0.029088 0.030824 0.028944 0.029089 ... 0.049261 0.049165 0.046193 0.038718 0.044205 0.044439 0.041883 ]

after BTS layer:  4

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.020067 0.018567 0.023811 0.029106 0.030843 0.028963 0.029107 ... 0.049292 0.049196 0.046223 0.038743 0.044234 0.044468 0.041910 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.477835 0.575663 0.296745 0.311111 0.385421 0.306280 0.311143 ... 0.672495 0.678279 0.833796 0.837641 0.897115 0.891831 0.914899 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.020065 0.018564 0.023809 0.029103 0.030842 0.028959 0.029104 ... 0.049290 0.049194 0.046216 0.038738 0.044228 0.044462 0.041906 ]

layer:  5
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  5

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.019959 -0.002721 -0.003060 0.021083 0.011837 -0.007406 0.015163 ... -0.000627 0.003576 -0.007637 -0.024577 -0.020641 -0.005350 -0.014515 ]

after BN layer:  5

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.013064 -0.009616 -0.009955 0.014188 0.004942 -0.014301 0.008267 ... 0.006009 0.010212 -0.001001 -0.017941 -0.014005 0.001286 -0.007879 ]

after BTS layer:  5

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.013072 -0.009623 -0.009962 0.014197 0.004945 -0.014310 0.008273 ... 0.006013 0.010219 -0.001002 -0.017952 -0.014014 0.001287 -0.007885 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.882649 -0.902071 -0.908806 0.839281 0.608599 -0.834109 0.855305 ... 0.706839 0.912584 -0.135049 -0.616867 -0.847325 0.172968 -0.835951 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.013071 -0.000001 -0.000000 0.014195 0.004944 -0.000002 0.008272 ... 0.006012 0.010218 -0.000064 -0.000002 -0.000001 0.001258 -0.000001 ]

layer:  6
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  6

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.004555 -0.004684 -0.004204 -0.006369 -0.005242 -0.004543 -0.003816 ... 0.024731 0.020503 0.032296 0.030897 0.012001 0.007642 0.016865 ]

after BN layer:  6

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.018283 0.018153 0.018633 0.016468 0.017595 0.018295 0.019021 ... 0.000824 -0.003405 0.008389 0.006989 -0.011906 -0.016266 -0.007042 ]

after cnnAddCipher layer:  6

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.038338 0.036708 0.042431 0.045557 0.048423 0.047240 0.048111 ... 0.050090 0.045765 0.054583 0.045708 0.032300 0.028174 0.034844 ]

after BTS layer:  6

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.038362 0.036732 0.042458 0.045586 0.048454 0.047270 0.048141 ... 0.050122 0.045795 0.054618 0.045738 0.032321 0.028192 0.034866 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.821347 0.738494 0.916513 0.858406 0.721892 0.785616 0.739513 ... 0.621507 0.850757 0.363727 0.852894 0.466911 0.284215 0.625874 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.038357 0.036727 0.042452 0.045584 0.048447 0.047269 0.048135 ... 0.050117 0.045791 0.054615 0.045734 0.032317 0.028191 0.034863 ]

layer:  7
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  7

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.016864 -0.037489 0.024147 -0.054996 0.028037 -0.049015 0.027577 ... 0.016740 -0.012469 -0.015735 0.013019 -0.028831 0.004860 0.009325 ]

after BN layer:  7

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.010185 0.018723 -0.002902 0.001216 0.000988 0.007198 0.000528 ... 0.012398 -0.020394 -0.020077 0.005094 -0.033172 -0.003066 0.004984 ]

after BTS layer:  7

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.010192 0.018735 -0.002904 0.001217 0.000988 0.007203 0.000528 ... 0.012406 -0.020407 -0.020090 0.005097 -0.033194 -0.003068 0.004987 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.912241 0.564398 -0.380355 0.163707 0.133194 0.795658 0.071380 ... 0.900690 -0.456867 -0.476405 0.623564 -0.520099 -0.400283 0.612774 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000000 0.018733 -0.000000 0.001181 0.000922 0.007202 0.000413 ... 0.012404 -0.000003 -0.000002 0.005096 -0.000001 -0.000000 0.004986 ]

layer:  8
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  8

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.009925 -0.001791 0.014774 0.000823 0.010615 -0.005532 0.006239 ... 0.003283 0.010929 -0.009968 0.016488 0.014732 0.012720 0.013519 ]

after BN layer:  8

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.002179 0.011535 0.007027 0.014148 0.002868 0.007794 -0.001508 ... 0.010661 0.022653 -0.002589 0.028212 0.022110 0.024444 0.020897 ]

after Down sample layer:  8

Level: 2 (logQ = 140)
Scale: 2^40.000460
Level: 2
ValuesTest: [-0.000000 0.000000 -0.000000 0.000000 0.000000 0.000000 -0.000000 ... 0.000000 0.000000 -0.000000 0.000000 0.000000 -0.000000 0.000000 ]

after cnnAddCipher layer:  8

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.002179 0.011535 0.007027 0.014148 0.002868 0.007794 -0.001508 ... 0.010661 0.022653 -0.002589 0.028212 0.022110 0.024444 0.020897 ]

after BTS layer:  8

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.002180 0.011542 0.007032 0.014157 0.002870 0.007799 -0.001509 ... 0.010668 0.022668 -0.002591 0.028230 0.022124 0.024460 0.020910 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.289615 0.914474 0.784330 0.841048 0.376198 0.831308 -0.202325 ... 0.916485 0.338325 -0.341611 0.285147 0.362874 0.279782 0.427094 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.002180 0.011541 0.007032 0.014156 0.002870 0.007797 -0.000011 ... 0.010666 0.022666 -0.000000 0.028229 0.022123 0.024459 0.020908 ]

layer:  9
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  9

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.007946 -0.025719 -0.005912 -0.042014 0.003648 -0.047937 0.004497 ... -0.006595 0.000483 -0.005463 0.012060 -0.004316 -0.000788 -0.001812 ]

after BN layer:  9

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.000749 -0.004472 -0.014607 -0.020767 -0.005048 -0.026689 -0.004198 ... -0.012489 0.008802 -0.011358 0.020379 -0.010211 0.007530 -0.007707 ]

after BTS layer:  9

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.000750 -0.004475 -0.014617 -0.020780 -0.005051 -0.026706 -0.004201 ... -0.012497 0.008808 -0.011365 0.020392 -0.010218 0.007535 -0.007712 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.101204 -0.560347 -0.819426 -0.434623 -0.619070 -0.261464 -0.530913 ... -0.898578 0.877675 -0.915879 0.457799 -0.912569 0.816311 -0.826489 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000099 -0.000000 -0.000002 -0.000003 -0.000001 -0.000003 -0.000000 ... -0.000002 0.008807 -0.000001 0.020389 -0.000000 0.007534 -0.000001 ]

layer:  10
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  10

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.009792 0.004213 -0.014415 -0.005326 -0.017104 -0.006819 -0.009444 ... -0.000463 -0.001724 0.000256 -0.001841 0.018347 0.004880 0.022263 ]

after BN layer:  10

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.012997 -0.004199 -0.017620 -0.013737 -0.020310 -0.015231 -0.012649 ... -0.000609 -0.001682 0.000109 -0.001799 0.018201 0.004922 0.022116 ]

after cnnAddCipher layer:  10

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.010818 0.007337 -0.010592 0.000412 -0.017441 -0.007437 -0.012660 ... 0.010052 0.020972 0.000109 0.026416 0.040314 0.029369 0.043014 ]

after BTS layer:  10

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.010825 0.007342 -0.010599 0.000412 -0.017452 -0.007442 -0.012668 ... 0.010059 0.020986 0.000109 0.026433 0.040339 0.029388 0.043041 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.917050 0.804511 -0.916108 0.055672 -0.650261 -0.810692 -0.894331 ... 0.910362 0.422768 0.014755 0.260269 0.890493 0.321201 0.914268 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000002 0.007341 -0.000001 0.000300 -0.000001 -0.000001 -0.000002 ... 0.010058 0.020983 0.000061 0.026430 0.040334 0.029384 0.043039 ]

layer:  11
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  11

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.014493 -0.010608 0.015002 -0.002684 0.013559 -0.011541 0.021805 ... -0.038104 -0.016973 -0.066805 -0.014249 -0.055350 -0.003310 -0.002307 ]

after BN layer:  11

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.002139 -0.011388 -0.001631 -0.003465 -0.003074 -0.012321 0.005172 ... -0.003600 -0.013488 -0.032302 -0.010763 -0.020846 0.000176 0.032196 ]

after BTS layer:  11

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.002141 -0.011396 -0.001632 -0.003467 -0.003076 -0.012329 0.005175 ... -0.003603 -0.013496 -0.032323 -0.010770 -0.020860 0.000176 0.032217 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.284570 -0.915674 -0.218529 -0.447846 -0.401249 -0.902365 0.631176 ... -0.463640 -0.868087 -0.467032 -0.916897 -0.430011 0.023801 0.460797 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000000 -0.000001 -0.000005 -0.000000 -0.000000 -0.000001 0.005175 ... -0.000000 -0.000001 -0.000004 -0.000002 -0.000003 0.000106 0.032213 ]

layer:  12
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  12

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.014732 -0.009417 -0.015998 -0.009449 -0.005382 -0.007472 -0.011210 ... 0.000423 -0.017360 -0.003165 -0.012687 -0.008737 0.000219 -0.003238 ]

after BN layer:  12

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.015924 -0.009571 -0.017190 -0.009604 -0.006574 -0.007627 -0.012402 ... 0.003313 -0.010723 -0.000275 -0.006049 -0.005847 0.006857 -0.000348 ]

after cnnAddCipher layer:  12

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.015926 -0.002234 -0.017191 -0.009304 -0.006575 -0.007627 -0.012404 ... 0.013366 0.010250 -0.000214 0.020368 0.034468 0.036226 0.042670 ]

after BTS layer:  12

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.015936 -0.002235 -0.017202 -0.009310 -0.006579 -0.007632 -0.012412 ... 0.013375 0.010257 -0.000214 0.020381 0.034490 0.036249 0.042697 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.746798 -0.296656 -0.666773 -0.894091 -0.751959 -0.821975 -0.900549 ... 0.872494 0.913048 -0.028975 0.458484 0.602075 0.710697 0.916094 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000002 -0.000000 -0.000001 -0.000001 -0.000001 -0.000001 -0.000001 ... 0.013374 0.010256 -0.000081 0.020378 0.034485 0.036245 0.042692 ]

layer:  13
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  13

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.006956 -0.014012 -0.010825 -0.014323 -0.002913 -0.023977 -0.016824 ... -0.007229 -0.007856 -0.011080 0.009164 -0.005811 0.015747 0.001336 ]

after BN layer:  13

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.004048 0.002344 0.007715 0.001772 -0.005820 -0.007621 0.001717 ... 0.002934 -0.008648 -0.015337 0.010488 0.004352 0.014955 -0.002920 ]

after BTS layer:  13

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.004051 0.002346 0.007720 0.001773 -0.005824 -0.007626 0.001718 ... 0.002936 -0.008654 -0.015347 0.010495 0.004355 0.014965 -0.002922 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.514420 0.310706 0.826970 0.237069 -0.690707 -0.821588 0.229787 ... 0.384289 -0.871746 -0.780970 0.915387 0.547539 0.801672 -0.382574 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.004051 0.002345 0.007719 0.001772 -0.000000 -0.000001 0.001715 ... 0.002936 -0.000000 -0.000001 0.010494 0.004354 0.014964 -0.000000 ]

layer:  14
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  14

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.030396 0.017985 -0.007825 0.017653 -0.039606 0.009972 0.001144 ... -0.000248 -0.053218 -0.017776 -0.012714 -0.003038 -0.018775 -0.027123 ]

after BN layer:  14

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.015384 0.021429 -0.007102 0.008974 -0.024594 0.013416 0.001868 ... -0.030424 -0.043245 -0.024691 -0.018457 -0.033214 -0.008802 -0.034038 ]

after Down sample layer:  14

Level: 2 (logQ = 140)
Scale: 2^40.000460
Level: 2
ValuesTest: [-0.000000 -0.000000 0.000000 -0.000000 -0.000000 0.000000 0.000000 ... -0.000000 0.000000 0.000000 -0.000000 0.000000 0.000000 -0.000000 ]

after cnnAddCipher layer:  14

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.015384 0.021429 -0.007102 0.008974 -0.024594 0.013416 0.001868 ... -0.030424 -0.043245 -0.024691 -0.018457 -0.033214 -0.008802 -0.034038 ]

after BTS layer:  14

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.015394 0.021443 -0.007106 0.008979 -0.024610 0.013425 0.001869 ... -0.030444 -0.043272 -0.024707 -0.018469 -0.033235 -0.008807 -0.034060 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.778313 0.397461 -0.789329 0.883777 -0.276583 0.870705 0.249503 ... -0.365942 -0.912253 -0.274651 -0.582197 -0.522669 -0.877659 -0.574754 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000001 0.021442 -0.000000 0.008978 -0.000001 0.013424 0.001868 ... -0.000001 -0.000002 -0.000001 -0.000002 -0.000001 -0.000001 -0.000004 ]

layer:  15
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  15

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.006350 0.012253 0.002502 -0.022111 -0.005230 0.006319 -0.016393 ... 0.001762 0.003824 -0.019446 -0.003495 0.001225 -0.001908 -0.013661 ]

after BN layer:  15

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.021243 0.011378 0.005618 -0.030439 -0.020123 0.005444 -0.013276 ... 0.020918 -0.015427 -0.011090 -0.006666 0.020381 -0.021159 -0.005306 ]

after BTS layer:  15

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.021257 0.011386 0.005622 -0.030459 -0.020136 0.005448 -0.013285 ... 0.020931 -0.015437 -0.011097 -0.006670 0.020394 -0.021173 -0.005309 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.407576 0.915747 0.672828 -0.366646 -0.473533 0.656939 -0.875645 ... 0.425904 -0.775885 -0.917051 -0.758767 0.457664 -0.412228 -0.643942 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000002 0.011385 0.005622 -0.000001 -0.000002 0.005448 -0.000001 ... 0.020929 -0.000001 -0.000002 -0.000000 0.020391 -0.000002 -0.000000 ]

layer:  16
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  16

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.002945 0.007923 -0.021720 0.013519 -0.013617 0.018174 -0.038141 ... 0.028270 -0.024463 -0.009508 -0.010954 0.019243 -0.004551 -0.002611 ]

after BN layer:  16

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.001526 0.000165 -0.015441 0.008226 -0.012199 0.010416 -0.031862 ... 0.000053 -0.024146 -0.005596 -0.020391 -0.008974 -0.004234 0.001301 ]

after cnnAddCipher layer:  16

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.001527 0.021596 -0.015441 0.017200 -0.012200 0.023834 -0.029995 ... 0.000052 -0.024148 -0.005597 -0.020394 -0.008976 -0.004235 0.001297 ]

after BTS layer:  16

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.001528 0.021610 -0.015451 0.017211 -0.012207 0.023849 -0.030014 ... 0.000052 -0.024163 -0.005601 -0.020407 -0.008981 -0.004238 0.001298 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.204879 0.388603 -0.775092 0.666198 -0.904847 0.295606 -0.346512 ... 0.006991 -0.286915 -0.670903 -0.456883 -0.883848 -0.534928 0.174441 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000010 0.021609 -0.000001 0.017210 -0.000001 0.023847 -0.000003 ... 0.000027 -0.000001 -0.000000 -0.000003 -0.000001 -0.000000 0.001270 ]

layer:  17
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  17

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.000636 -0.011452 0.003560 -0.008738 -0.012504 -0.017383 -0.000662 ... -0.021888 -0.014952 -0.021621 -0.013994 -0.018514 -0.015374 -0.021944 ]

after BN layer:  17

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.009425 -0.015251 -0.005020 -0.006977 -0.021294 -0.021181 -0.009243 ... -0.011710 -0.018888 -0.010214 -0.022249 -0.008336 -0.019311 -0.010538 ]

after BTS layer:  17

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.009431 -0.015260 -0.005023 -0.006981 -0.021307 -0.021195 -0.009249 ... -0.011718 -0.018900 -0.010221 -0.022263 -0.008342 -0.019323 -0.010545 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [-0.897383 -0.785744 -0.616364 -0.780894 -0.404804 -0.410989 -0.892322 ... -0.912593 -0.553391 -0.912610 -0.356343 -0.858470 -0.525495 -0.915755 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [-0.000001 -0.000001 -0.000001 -0.000000 -0.000001 -0.000002 -0.000001 ... -0.000001 -0.000001 -0.000000 -0.000001 -0.000000 -0.000001 -0.000001 ]

layer:  18
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  18

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-0.000790 -0.018956 -0.017552 -0.033107 0.003609 -0.025392 -0.014608 ... -0.026475 -0.009914 -0.013170 -0.014762 -0.021710 -0.008104 -0.015212 ]

after BN layer:  18

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.000640 -0.020625 0.000687 -0.020553 0.005039 -0.027060 0.003632 ... -0.020840 -0.007191 -0.005084 -0.005895 -0.016076 -0.005381 -0.007126 ]

after cnnAddCipher layer:  18

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [0.000630 0.000974 0.000687 -0.003351 0.005038 -0.003225 0.003629 ... -0.020813 -0.007193 -0.005084 -0.005898 -0.016077 -0.005381 -0.005856 ]

after BTS layer:  18

Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.000630 0.000975 0.000687 -0.003354 0.005041 -0.003227 0.003632 ... -0.020826 -0.007197 -0.005088 -0.005902 -0.016087 -0.005385 -0.005860 ]


Level: 9 (logQ = 420)
Scale: 2^40.000000
Level: 9
ValuesTest: [0.085159 0.131409 0.092788 -0.434481 0.618141 -0.419390 0.466991 ... -0.431972 -0.795302 -0.622663 -0.697395 -0.737680 -0.651054 -0.693836 ]

after ReLU_cipher

Level: 3 (logQ = 180)
Scale: 2^40.000227
Level: 3
ValuesTest: [0.000520 0.000907 0.000582 -0.000000 0.005041 -0.000000 0.003631 ... -0.000003 -0.000000 -0.000001 -0.000001 -0.000002 -0.000000 -0.000000 ]

layer:  19
after averagePoolingCipherScale 

Level: 2 (logQ = 140)
Scale: 2^40.000460
Level: 2
ValuesTest: [1.770048 1.191831 1.456664 0.061683 0.359493 2.185026 0.513155 ... 0.000000 0.000000 0.000000 0.000000 0.000000 -0.000000 0.000000 ]

after matrixMultiplicationCipher 

Level: 1 (logQ = 101)
Scale: 2^40.000922
Level: 1
ValuesTest: [-6.612157 2.816876 1.613201 22.080946 -6.076473 5.859961 -3.661126 ... -0.000000 0.000000 -0.000000 -0.000000 0.000000 -0.000000 -0.000000 ]

( 
(-6.612156678112521+6.115766229879842e-08i)
(2.816876357057792+1.6294331872540412e-07i)
(1.6132014665297207-6.22770112204178e-08i)
(22.08094600533181+5.0343708599447285e-08i)
(-6.076473282833049+2.3554065026211684e-08i)
(5.859961075525141+6.526185132637641e-09i)
(-3.6611257360832368-6.916683960526196e-08i)
(-7.542186996339533+4.9385831697193135e-08i)
(-2.047243841089629+2.509425526967958e-07i)
(-6.429972721459737+1.0236478117125454e-07i)
 )
image label:  3
inferred label:  3
max score:  22.08094600533181
The infer operation took 17m44.312182094s
