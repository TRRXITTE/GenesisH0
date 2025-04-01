#include <Python.h>
#include "neoscrypt.h"

static PyObject *neoscrypt_getpowhash(PyObject *self, PyObject *args) {
    PyObject *input;
    unsigned char output[32];

    // Parse input as bytes ("y" format specifier)
    if (!PyArg_ParseTuple(args, "y", &input)) {
        return NULL;
    }

    Py_INCREF(input);
    // Call neoscrypt with bytes input
    neoscrypt((unsigned char *)PyBytes_AsString(input), output);
    Py_DECREF(input);

    // Return the output as a bytes object
    return PyBytes_FromStringAndSize((char *)output, 32);
}

static PyMethodDef NeoScryptMethods[] = {
    {"neoscrypt", neoscrypt_getpowhash, METH_VARARGS, "Calculate NeoScrypt PoW hash"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef neoscryptmodule = {
    PyModuleDef_HEAD_INIT,
    "neoscrypt",
    NULL,
    -1,
    NeoScryptMethods
};

PyMODINIT_FUNC PyInit_neoscrypt(void) {
    return PyModule_Create(&neoscryptmodule);
}