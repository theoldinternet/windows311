' Bubble Sort Demo
CLS
PRINT "Bubble Sort Demo"
PRINT "----------------"
DIM a(10)
RANDOMIZE TIMER
PRINT "Unsorted: ";
FOR i = 1 TO 10
    a(i) = INT(RND * 100) + 1
    PRINT a(i); " ";
NEXT i
PRINT

' Bubble sort
FOR i = 1 TO 9
    FOR j = 1 TO 10 - i
        IF a(j) > a(j+1) THEN
            SWAP a(j), a(j+1)
        END IF
    NEXT j
NEXT i

PRINT "Sorted:   ";
FOR i = 1 TO 10
    PRINT a(i); " ";
NEXT i
PRINT
