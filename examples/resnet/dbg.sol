2

CKKS parameters: logN = 16, logSlots = 15, h = 192, logQP = 1692, levels = 31, scale= 2^42.000000, sigma = 3.200000, message scaling(log2) = 20.997885 

Generating bootstrapping keys...
Repeated free rotations:  [0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 3 5 6 7 9 10 11 12 13 14 15 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 33 56 62 63 66 84 124 132 959 960 990 991 1008 1023 1036 1064 1092 1952 1982 1983 2016 2044 2047 2072 2078 2100 3007 3024 3040 3052 3070 3071 3072 3080 3108 4031 4032 4062 4063 4095 5023 5024 5054 5055 5087 5118 5119 5120 6047 6078 6079 6111 6112 6142 6143 6144 7071 7102 7103 7135 7166 7167 7168 8095 8126 8127 8159 8190 8191 9149 9183 9184 9213 9215 9216 10173 10207 10208 10237 10239 10240 11197 11231 11232 11261 11263 11264 12221 12255 12256 12285 12287 12288 13214 13216 13246 13278 13279 13280 13310 13311 13312 14238 14240 14270 14302 14303 14304 14334 14335 15262 15264 15294 15326 15327 15328 15358 15359 15360 16286 16288 16318 16350 16351 16352 16382 16383 17311 17375 18335 18399 18432 19359 19423 20383 20447 20480 21405 21406 21437 21469 21470 21471 21501 21504 22429 22430 22461 22493 22494 22495 22525 22528 23453 23454 23485 23517 23518 23519 23549 24477 24478 24509 24541 24542 24543 24573 24576 25501 25565 25568 25600 26525 26589 26592 26624 27549 27613 27616 27648 28573 28637 28640 28672 29600 29632 29664 29696 30624 30656 30688 30720 31648 31680 31712 31743 31744 31774 32636 32640 32644 32672 32702 32704 32706 32735 32736 32737 32759 32760 32761 32762 32763 32764 32765 32766 32767 14336 224 928 544 896 672 832 288 704 192 160 448 736 608 864 352 768 96 800 480 384 640 576 416 320 992 32752 48 40 32512 1536 2560 3584]
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
total parmas.N block of symmetric enc, keystream block 0:  [89863279 189328813 24361983 111991553 42175004 126017409 82404487 46953677 88169678 239287919 189452318 172581304 48198918 113260594 99993781 46944662]
after HalfBoot: 

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.015847 0.016312 0.019225 0.019719 0.016809 0.014863 0.017770 ... -0.000004 -0.000009 -0.000002 -0.000012 -0.000003 -0.000004 -0.000003 ]


Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.000013 0.000005 -0.000007 -0.000000 -0.000013 -0.000011 -0.000002 ... -0.000007 0.000000 -0.000002 -0.000011 -0.000003 -0.000002 -0.000010 ]


Level: 15 (logQ = 681)
Scale: 2^42.000001
Level: 15
ValuesTest: [0.015847 0.016312 0.019225 0.019719 0.016809 0.014863 0.017770 ... -0.000000 -0.000000 -0.000000 -0.000000 -0.000000 -0.000000 -0.000000 ]

Time transcipher : %v 4m27.700577772s
totalLevel 31 ResidualModuli:  17
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

Level: 0 (logQ = 51)
Scale: 2^42.000038
Level: 0
ValuesTest: [-0.010612 -0.013156 -0.013125 -0.012459 -0.012430 -0.012788 -0.012531 ... -0.004102 -0.003968 -0.010107 -0.016269 -0.016283 -0.012773 -0.008841 ]

after BN

Level: 0 (logQ = 51)
Scale: 2^42.000038
Level: 0
ValuesTest: [-0.017879 -0.020423 -0.020393 -0.019726 -0.019697 -0.020056 -0.019799 ... 0.030540 0.030675 0.024536 0.018373 0.018360 0.021870 0.025802 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after btp real, stage:  0

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.018394 -0.020643 -0.020313 -0.020079 -0.020063 -0.019579 -0.019622 ... 0.030745 0.030872 0.024220 0.018790 0.018534 0.022022 0.025637 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000043 -0.000047 -0.000047 -0.000046 -0.000046 -0.000044 -0.000044 ... 0.030679 0.030805 0.024169 0.018748 0.018491 0.021975 0.025583 ]

layer:  1
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  1

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.009782 0.017975 0.024370 0.028361 0.027161 0.025025 0.026554 ... 0.050362 0.047349 0.040549 0.036028 0.036868 0.030393 0.025987 ]

after BN layer:  1

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.016518 -0.008325 -0.001931 0.002061 0.000861 -0.001275 0.000253 ... -0.017778 -0.020791 -0.027591 -0.032112 -0.031272 -0.037747 -0.042153 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  1

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.016992 -0.008651 -0.002594 0.001186 0.001097 -0.001069 0.000529 ... -0.018118 -0.021481 -0.028095 -0.032874 -0.032086 -0.038233 -0.043676 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000038 -0.000019 -0.000006 0.001144 0.001044 -0.000057 0.000413 ... -0.000042 -0.000047 -0.000059 -0.000073 -0.000074 -0.000088 -0.000098 ]

layer:  2
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  2

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.006368 -0.006313 -0.005886 -0.004220 -0.003504 -0.003935 -0.004068 ... 0.003939 0.003462 -0.000928 -0.000115 0.006490 0.005217 0.000401 ]

after BN layer:  2

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.003689 0.003745 0.004171 0.005838 0.006554 0.006123 0.005990 ... 0.001752 0.001275 -0.003115 -0.002302 0.004303 0.003030 -0.001786 ]

after cnnAddCipher layer:  2

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.003647 0.003698 0.004125 0.005793 0.006509 0.006080 0.005947 ... 0.032006 0.031654 0.020720 0.016186 0.022537 0.024700 0.023443 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  2

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.003967 0.004554 0.004462 0.005655 0.006727 0.005910 0.005843 ... 0.032652 0.032115 0.021288 0.016734 0.023021 0.025272 0.023549 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.003958 0.004543 0.004452 0.005642 0.006711 0.005897 0.005830 ... 0.032578 0.032041 0.021241 0.016696 0.022970 0.025219 0.023498 ]

layer:  3
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  3

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.021846 0.038846 0.039506 0.035384 0.032521 0.033019 0.032310 ... -0.006916 -0.008551 -0.002353 0.007733 0.010750 -0.003137 -0.009037 ]

after BN layer:  3

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.010547 0.027546 0.028207 0.024085 0.021222 0.021720 0.021011 ... -0.006476 -0.008111 -0.001913 0.008173 0.011190 -0.002697 -0.008597 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  3

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.010067 0.028255 0.029011 0.024801 0.021642 0.021986 0.020901 ... -0.007147 -0.007930 -0.002034 0.007492 0.011511 -0.002849 -0.008403 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.010044 0.028195 0.028947 0.024750 0.021595 0.021938 0.020854 ... -0.000016 -0.000018 -0.000004 0.007475 0.011485 -0.000006 -0.000019 ]

layer:  4
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  4

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.015164 -0.016574 -0.011995 -0.007466 -0.006277 -0.008536 -0.008237 ... 0.018087 0.019486 0.025430 0.024586 0.023651 0.021115 0.019002 ]

after BN layer:  4

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.015749 0.014339 0.018919 0.023447 0.024636 0.022378 0.022676 ... 0.016736 0.018135 0.024079 0.023235 0.022300 0.019764 0.017651 ]

after cnnAddCipher layer:  4

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.019653 0.018820 0.023309 0.029011 0.031255 0.028193 0.028426 ... 0.048864 0.049733 0.045026 0.039700 0.044952 0.044634 0.040824 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  4

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.020183 0.019122 0.023237 0.030046 0.032320 0.029476 0.028908 ... 0.049725 0.051080 0.046171 0.040590 0.046273 0.044838 0.041731 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.020137 0.019079 0.023185 0.029980 0.032246 0.029410 0.028845 ... 0.049613 0.050964 0.046065 0.040496 0.046165 0.044736 0.041638 ]

layer:  5
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  5

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.020805 -0.002462 -0.004799 0.022517 0.011957 -0.009770 0.016698 ... -0.000590 0.003850 -0.008444 -0.025793 -0.020893 -0.005920 -0.014940 ]

after BN layer:  5

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.013910 -0.009358 -0.011694 0.015622 0.005062 -0.016666 0.009802 ... 0.006046 0.010486 -0.001808 -0.019158 -0.014257 0.000716 -0.008304 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  5

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.013784 -0.009428 -0.011070 0.016586 0.005518 -0.016747 0.010305 ... 0.006834 0.010772 -0.001975 -0.020715 -0.014644 0.000707 -0.008952 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.013753 -0.000022 -0.000026 0.016548 0.005506 -0.000038 0.010282 ... 0.006818 0.010747 -0.000004 -0.000047 -0.000034 0.000603 -0.000020 ]

layer:  6
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  6

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.004490 -0.004998 -0.004802 -0.007196 -0.006521 -0.005229 -0.004551 ... 0.026365 0.020291 0.034174 0.030277 0.011480 0.007957 0.017360 ]

after BN layer:  6

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.018348 0.017839 0.018035 0.015641 0.016316 0.017608 0.018287 ... 0.002458 -0.003617 0.010266 0.006370 -0.012427 -0.015950 -0.006548 ]

after cnnAddCipher layer:  6

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.038206 0.036654 0.040900 0.045207 0.048116 0.046611 0.046733 ... 0.051385 0.046642 0.055693 0.046305 0.033099 0.028166 0.034514 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  6

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.038482 0.037109 0.041051 0.046640 0.049124 0.047112 0.047875 ... 0.052635 0.047883 0.057698 0.047922 0.034046 0.029189 0.035510 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.038393 0.037026 0.040958 0.046533 0.049014 0.047007 0.047767 ... 0.052515 0.047774 0.057578 0.047813 0.033967 0.029124 0.035431 ]

layer:  7
ki: 1, hi: 32, wi: 32, ci: 16, ti: 16, pi: 2, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  7

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.017400 -0.038078 0.023573 -0.054843 0.027008 -0.047969 0.026068 ... 0.016869 -0.011308 -0.016488 0.014849 -0.029476 0.005857 0.009045 ]

after BN layer:  7

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.009649 0.018134 -0.003476 0.001369 -0.000041 0.008243 -0.000981 ... 0.012527 -0.019233 -0.020829 0.006924 -0.033818 -0.002068 0.004703 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  7

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.009554 0.018280 -0.003882 0.001122 0.000053 0.008143 -0.000943 ... 0.012776 -0.019735 -0.021692 0.006977 -0.034348 -0.002864 0.004767 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000022 0.018237 -0.000009 0.001073 0.000028 0.008124 -0.000074 ... 0.012746 -0.000044 -0.000047 0.006961 -0.000080 -0.000006 0.004756 ]

layer:  8
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  8

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.009560 -0.001820 0.015393 0.000883 0.011425 -0.005404 0.007006 ... 0.003004 0.012281 -0.010259 0.017020 0.015077 0.013120 0.014245 ]

after BN layer:  8

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.001813 0.011506 0.007646 0.014208 0.003678 0.007922 -0.000740 ... 0.010383 0.024005 -0.002880 0.028745 0.022455 0.024844 0.021623 ]

after Down sample layer:  8

Level: 1 (logQ = 93)
Scale: 2^42.013387
Level: 1
ValuesTest: [-0.000000 0.000000 -0.000000 0.000000 0.000000 0.000000 0.000000 ... 0.000000 0.000000 0.000000 -0.000000 -0.000000 0.000000 0.000000 ]

after cnnAddCipher layer:  8

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.001813 0.011506 0.007646 0.014208 0.003678 0.007922 -0.000740 ... 0.010383 0.024005 -0.002880 0.028745 0.022455 0.024844 0.021623 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  8

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.001338 0.011865 0.008108 0.014934 0.003813 0.007405 -0.000549 ... 0.011481 0.024131 -0.003524 0.029486 0.022951 0.025740 0.021909 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.001312 0.011838 0.008089 0.014900 0.003805 0.007388 -0.000115 ... 0.011455 0.024080 -0.000008 0.029420 0.022900 0.025685 0.021861 ]

layer:  9
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  9

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.007438 -0.025262 -0.006385 -0.041538 0.004014 -0.048304 0.005204 ... -0.007073 0.000568 -0.005184 0.013679 -0.003804 -0.000043 -0.001188 ]

after BN layer:  9

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.001257 -0.004015 -0.015080 -0.020290 -0.004681 -0.027057 -0.003491 ... -0.012967 0.008887 -0.011079 0.021997 -0.009698 0.008276 -0.007082 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  9

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.001583 -0.004806 -0.015704 -0.020806 -0.005016 -0.027857 -0.003771 ... -0.012774 0.008855 -0.010522 0.022926 -0.009853 0.009563 -0.007110 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000010 -0.000011 -0.000035 -0.000047 -0.000012 -0.000058 -0.000009 ... -0.000030 0.008835 -0.000024 0.022875 -0.000022 0.009541 -0.000016 ]

layer:  10
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  10

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.009683 0.004494 -0.014155 -0.004671 -0.016928 -0.004588 -0.010311 ... -0.000289 -0.001897 -0.000463 -0.001953 0.019800 0.005484 0.024746 ]

after BN layer:  10

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.012888 -0.003917 -0.017360 -0.013083 -0.020134 -0.012999 -0.013516 ... -0.000436 -0.001855 -0.000609 -0.001911 0.019653 0.005526 0.024600 ]

after cnnAddCipher layer:  10

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.011594 0.007757 -0.009383 0.001612 -0.016382 -0.005714 -0.013630 ... 0.010861 0.021891 -0.000617 0.027102 0.042237 0.030855 0.046159 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  10

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.011896 0.008383 -0.008849 0.001492 -0.016950 -0.004971 -0.013774 ... 0.010929 0.022591 -0.000701 0.026935 0.042886 0.031400 0.046191 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000027 0.008365 -0.000020 0.001477 -0.000038 -0.000012 -0.000031 ... 0.010904 0.022541 -0.000105 0.026879 0.042789 0.031329 0.046084 ]

layer:  11
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  11

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.014882 -0.009846 0.015611 -0.002874 0.012017 -0.011568 0.020995 ... -0.041224 -0.018155 -0.070309 -0.015224 -0.058976 -0.003774 -0.000397 ]

after BN layer:  11

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.001750 -0.010627 -0.001022 -0.003654 -0.004615 -0.012349 0.004363 ... -0.006720 -0.014670 -0.035806 -0.011739 -0.024473 -0.000288 0.034106 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  11

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.002403 -0.010960 -0.000518 -0.003669 -0.005061 -0.013127 0.003549 ... -0.006677 -0.015026 -0.036649 -0.012159 -0.025688 0.000143 0.034774 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000005 -0.000025 -0.000116 -0.000008 -0.000012 -0.000030 0.003541 ... -0.000015 -0.000034 -0.000085 -0.000028 -0.000055 0.000083 0.034695 ]

layer:  12
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  12

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.015469 -0.009785 -0.015225 -0.009860 -0.006013 -0.007596 -0.010827 ... 0.000884 -0.017592 -0.003683 -0.012502 -0.009762 0.001221 -0.004073 ]

after BN layer:  12

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.016661 -0.009940 -0.016417 -0.010014 -0.007205 -0.007751 -0.012019 ... 0.003773 -0.010954 -0.000793 -0.005865 -0.006872 0.007858 -0.001183 ]

after cnnAddCipher layer:  12

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.016687 -0.001691 -0.016437 -0.008558 -0.007243 -0.007762 -0.012049 ... 0.014527 0.011275 -0.000896 0.020642 0.035324 0.038754 0.044264 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  12

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.018232 -0.001104 -0.017283 -0.009637 -0.006915 -0.008660 -0.013019 ... 0.014904 0.011161 -0.000351 0.020890 0.035824 0.040167 0.045484 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000042 -0.000052 -0.000038 -0.000022 -0.000015 -0.000019 -0.000030 ... 0.014871 0.011136 -0.000107 0.020843 0.035743 0.040074 0.045382 ]

layer:  13
ki: 2, hi: 16, wi: 16, ci: 32, ti: 8, pi: 4, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  13

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.008516 -0.012547 -0.010587 -0.015638 -0.003546 -0.022990 -0.017452 ... -0.008944 -0.006877 -0.014829 0.008474 -0.007074 0.015321 0.000725 ]

after BN layer:  13

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.005608 0.003809 0.007954 0.000457 -0.006454 -0.006634 0.001089 ... 0.001219 -0.007669 -0.019086 0.009798 0.003089 0.014529 -0.003531 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  13

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.005232 0.003990 0.008368 -0.000152 -0.006489 -0.007612 0.000625 ... 0.001679 -0.007698 -0.019063 0.009725 0.002676 0.014157 -0.003541 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.005221 0.003982 0.008349 -0.000063 -0.000015 -0.000018 0.000514 ... 0.001672 -0.000018 -0.000043 0.009703 0.002671 0.014125 -0.000008 ]

layer:  14
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  14

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.031913 0.019818 -0.005979 0.018816 -0.039402 0.011423 0.003865 ... 0.001914 -0.052447 -0.017919 -0.013196 -0.003405 -0.015772 -0.026601 ]

after BN layer:  14

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.016901 0.023262 -0.005256 0.010137 -0.024390 0.014867 0.004589 ... -0.028262 -0.042473 -0.024834 -0.018939 -0.033581 -0.005798 -0.033516 ]

after Down sample layer:  14

Level: 1 (logQ = 93)
Scale: 2^42.013387
Level: 1
ValuesTest: [-0.000000 -0.000000 0.000000 -0.000000 -0.000000 -0.000000 0.000000 ... 0.000000 0.000000 0.000000 -0.000000 0.000000 0.000000 -0.000000 ]

after cnnAddCipher layer:  14

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.016901 0.023262 -0.005256 0.010137 -0.024390 0.014867 0.004589 ... -0.028262 -0.042473 -0.024834 -0.018939 -0.033581 -0.005798 -0.033516 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  14

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.017340 0.024228 -0.005679 0.010125 -0.024992 0.015208 0.005237 ... -0.029146 -0.043062 -0.025099 -0.019156 -0.034655 -0.005399 -0.034354 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000039 0.024177 -0.000013 0.010103 -0.000052 0.015174 0.005225 ... -0.000065 -0.000097 -0.000052 -0.000043 -0.000080 -0.000012 -0.000080 ]

layer:  15
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  15

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.006456 0.014504 0.001501 -0.022379 -0.004066 0.006252 -0.018331 ... 0.000926 0.004509 -0.018814 -0.003688 0.000499 -0.002568 -0.013274 ]

after BN layer:  15

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.021349 0.013630 0.004618 -0.030707 -0.018959 0.005377 -0.015214 ... 0.020082 -0.014742 -0.010459 -0.006859 0.019654 -0.021819 -0.004918 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  15

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.021003 0.013702 0.004890 -0.031670 -0.018722 0.005582 -0.014894 ... 0.020551 -0.015840 -0.010906 -0.007270 0.019976 -0.021826 -0.004736 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000047 0.013672 0.004878 -0.000072 -0.000043 0.005569 -0.000034 ... 0.020504 -0.000036 -0.000025 -0.000016 0.019931 -0.000047 -0.000011 ]

layer:  16
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  16

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.002756 0.007896 -0.022991 0.013380 -0.016058 0.021153 -0.044100 ... 0.030085 -0.025108 -0.008823 -0.010650 0.018681 -0.003682 -0.000253 ]

after BN layer:  16

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.001337 0.000138 -0.016713 0.008087 -0.014639 0.013395 -0.037821 ... 0.001868 -0.024791 -0.004911 -0.020087 -0.009536 -0.003365 0.003659 ]

after cnnAddCipher layer:  16

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.001375 0.023980 -0.016725 0.018050 -0.014691 0.028360 -0.032668 ... 0.001805 -0.024887 -0.004963 -0.020129 -0.009615 -0.003377 0.003581 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  16

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.001542 0.024186 -0.017249 0.019510 -0.015243 0.028611 -0.032883 ... 0.001385 -0.025507 -0.004242 -0.020123 -0.009222 -0.002936 0.004011 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000012 0.024135 -0.000038 0.019467 -0.000034 0.028549 -0.000073 ... 0.001363 -0.000054 -0.000009 -0.000046 -0.000021 -0.000006 0.004002 ]

layer:  17
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  17

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.001086 -0.011816 0.004125 -0.008791 -0.011939 -0.016787 -0.001841 ... -0.021163 -0.015500 -0.022657 -0.014901 -0.018775 -0.015718 -0.024323 ]

after BN layer:  17

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-0.007703 -0.015615 -0.004456 -0.007030 -0.020728 -0.020585 -0.010422 ... -0.010985 -0.019436 -0.011251 -0.023155 -0.008597 -0.019654 -0.012917 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  17

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [-0.007964 -0.015965 -0.004426 -0.006922 -0.020985 -0.020876 -0.010491 ... -0.011012 -0.019774 -0.011755 -0.024233 -0.009298 -0.020120 -0.013113 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [-0.000018 -0.000037 -0.000010 -0.000015 -0.000047 -0.000047 -0.000024 ... -0.000026 -0.000044 -0.000026 -0.000051 -0.000022 -0.000046 -0.000030 ]

layer:  18
ki: 4, hi: 8, wi: 8, ci: 64, ti: 4, pi: 8, logn: 15
before conv encode, LogSlots:  15
after convolution layer:  18

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.004884 -0.023000 -0.016246 -0.036037 0.010005 -0.028951 -0.011731 ... -0.026172 -0.003506 -0.010458 -0.013331 -0.018681 -0.004238 -0.015226 ]

after BN layer:  18

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.006314 -0.024669 0.001993 -0.023483 0.011435 -0.030619 0.006509 ... -0.020538 -0.000783 -0.002372 -0.004465 -0.013046 -0.001515 -0.007140 ]

after cnnAddCipher layer:  18

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [0.006302 -0.000867 0.001956 -0.004286 0.011402 -0.002465 0.006437 ... -0.019194 -0.000836 -0.002382 -0.004510 -0.013068 -0.001521 -0.003194 ]

C2S parmas LogSlots:  15
scale after sine,:  42
after BTS layer:  18

Level: 16 (logQ = 723)
Scale: 2^42.000000
Level: 16
ValuesTest: [0.006166 -0.000691 0.002538 -0.004395 0.011960 -0.002830 0.007341 ... -0.019761 -0.001219 -0.002562 -0.004359 -0.013402 -0.001297 -0.003219 ]

after ReLU_cipher

Level: 2 (logQ = 135)
Scale: 2^42.006688
Level: 2
ValuesTest: [0.006152 -0.000106 0.002532 -0.000010 0.011933 -0.000006 0.007324 ... -0.000044 -0.000038 -0.000006 -0.000010 -0.000030 -0.000030 -0.000007 ]

layer:  19
after averagePoolingCipherScale 

Level: 1 (logQ = 93)
Scale: 2^42.013387
Level: 1
ValuesTest: [1.960846 1.334922 1.358940 0.065033 0.325089 2.369070 0.507002 ... -0.000000 0.000000 -0.000000 0.000000 -0.000000 -0.000000 -0.000000 ]

after matrixMultiplicationCipher 

Level: 0 (logQ = 51)
Scale: 2^42.026787
Level: 0
ValuesTest: [-6.029958 4.437666 1.797976 22.832603 -6.158875 6.219699 -4.500184 ... 0.000000 -0.000000 -0.000000 0.000000 -0.000000 -0.000000 -0.000000 ]

( 
(-6.029958086393964-4.960193707728927e-10i)
(4.437666380981144+1.9869449528108147e-08i)
(1.7979762948976457-2.2308136943065791e-10i)
(22.83260261746699-1.3539321977446136e-08i)
(-6.158875154228264+6.7314655184853595e-09i)
(6.219698962734848-1.2470624306614537e-08i)
(-4.500183858216229-1.7615722029321436e-08i)
(-9.083221156691199-1.7364212674257943e-08i)
(-3.2080819133492255-2.1508932727034983e-08i)
(-6.3021712552739535+1.5696302586816003e-08i)
 )
image label:  3
inferred label:  3
max score:  22.83260261746699
The infer operation took 14m25.332046696s
