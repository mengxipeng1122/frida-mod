
#pragma once

typedef void* EGLDisplay;
typedef void* EGLSurface;
typedef int   EGLBoolean;

EGLBoolean eglSwapBuffers(  EGLDisplay display, EGLSurface surface);
