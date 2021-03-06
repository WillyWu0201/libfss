# Function Secret Sharing (FSS) Library

This is a function secret sharing (FSS) library for Go. A C++ version (used in the paper) will be released soon!

This library is based the following papers:

- Boyle, Elette, Niv Gilboa, and Yuval Ishai. "[Function Secret Sharing: Improvements and Extensions.](https://pdfs.semanticscholar.org/6b3a/ea37625702e98e5033e1107403e319b4df01.pdf)" Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security. ACM, 2016.

- Boyle, Elette, Niv Gilboa, and Yuval Ishai. "[Function secret sharing.](https://cs.idc.ac.il/~elette/FunctionSecretSharing.pdf)" Annual International Conference on the Theory and Applications of Cryptographic Techniques. Springer Berlin Heidelberg, 2015. 

This implementation uses the techniques described in: 

Frank Wang, Catherine Yun, Shafi Goldwasser, Vinod Vaikuntanathan, and Matei Zaharia. "[Splinter: Practical Private Queries on Public Data.](https://frankwang.org/papers/wang-splinter.pdf)" NSDI 2017.

We created a Go library for portability reasons. The main FSS files are in libfss/. Doing a go install on the test/ folder will create the test programs. 

For any questions, feel free to create an issue, submit a pull request, or email Frank Wang at frankw@mit.edu.

