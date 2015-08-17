# Android_Utils

LockType usage

int lockType = LockType.getCurrent(getContentResolver());

switch (lockType) 
{
    case LockType.FACE_WITH_PATTERN:
    case LockType.FACE_WITH_PIN:
    case LockType.PATTERN:
        /* do something */
        break;
}

// if you want only "Face Unlock" no matter with which additional method
if (lockType >= LockType.FACE_WITH_PATTERN && lockType <= LockType.FACE_WITH_SOMETHING_ELSE)
{
    /* do something */
}
