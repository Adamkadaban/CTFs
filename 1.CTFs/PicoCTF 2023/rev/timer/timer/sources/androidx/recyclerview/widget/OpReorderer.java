package androidx.recyclerview.widget;

import androidx.recyclerview.widget.AdapterHelper;
import java.util.List;
/* loaded from: classes.dex */
class OpReorderer {
    final Callback mCallback;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface Callback {
        AdapterHelper.UpdateOp obtainUpdateOp(int i, int i2, int i3, Object obj);

        void recycleUpdateOp(AdapterHelper.UpdateOp updateOp);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public OpReorderer(Callback callback) {
        this.mCallback = callback;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reorderOps(List<AdapterHelper.UpdateOp> ops) {
        while (true) {
            int badMove = getLastMoveOutOfOrder(ops);
            if (badMove != -1) {
                swapMoveOp(ops, badMove, badMove + 1);
            } else {
                return;
            }
        }
    }

    private void swapMoveOp(List<AdapterHelper.UpdateOp> list, int badMove, int next) {
        AdapterHelper.UpdateOp moveOp = list.get(badMove);
        AdapterHelper.UpdateOp nextOp = list.get(next);
        switch (nextOp.cmd) {
            case 1:
                swapMoveAdd(list, badMove, moveOp, next, nextOp);
                return;
            case 2:
                swapMoveRemove(list, badMove, moveOp, next, nextOp);
                return;
            case 3:
            default:
                return;
            case 4:
                swapMoveUpdate(list, badMove, moveOp, next, nextOp);
                return;
        }
    }

    void swapMoveRemove(List<AdapterHelper.UpdateOp> list, int movePos, AdapterHelper.UpdateOp moveOp, int removePos, AdapterHelper.UpdateOp removeOp) {
        boolean moveIsBackwards;
        AdapterHelper.UpdateOp extraRm = null;
        boolean revertedMove = false;
        if (moveOp.positionStart < moveOp.itemCount) {
            moveIsBackwards = false;
            if (removeOp.positionStart == moveOp.positionStart && removeOp.itemCount == moveOp.itemCount - moveOp.positionStart) {
                revertedMove = true;
            }
        } else {
            moveIsBackwards = true;
            if (removeOp.positionStart == moveOp.itemCount + 1 && removeOp.itemCount == moveOp.positionStart - moveOp.itemCount) {
                revertedMove = true;
            }
        }
        if (moveOp.itemCount < removeOp.positionStart) {
            removeOp.positionStart--;
        } else if (moveOp.itemCount < removeOp.positionStart + removeOp.itemCount) {
            removeOp.itemCount--;
            moveOp.cmd = 2;
            moveOp.itemCount = 1;
            if (removeOp.itemCount == 0) {
                list.remove(removePos);
                this.mCallback.recycleUpdateOp(removeOp);
                return;
            }
            return;
        }
        if (moveOp.positionStart <= removeOp.positionStart) {
            removeOp.positionStart++;
        } else if (moveOp.positionStart < removeOp.positionStart + removeOp.itemCount) {
            int remaining = (removeOp.positionStart + removeOp.itemCount) - moveOp.positionStart;
            extraRm = this.mCallback.obtainUpdateOp(2, moveOp.positionStart + 1, remaining, null);
            removeOp.itemCount = moveOp.positionStart - removeOp.positionStart;
        }
        if (revertedMove) {
            list.set(movePos, removeOp);
            list.remove(removePos);
            this.mCallback.recycleUpdateOp(moveOp);
            return;
        }
        if (moveIsBackwards) {
            if (extraRm != null) {
                if (moveOp.positionStart > extraRm.positionStart) {
                    moveOp.positionStart -= extraRm.itemCount;
                }
                if (moveOp.itemCount > extraRm.positionStart) {
                    moveOp.itemCount -= extraRm.itemCount;
                }
            }
            if (moveOp.positionStart > removeOp.positionStart) {
                moveOp.positionStart -= removeOp.itemCount;
            }
            if (moveOp.itemCount > removeOp.positionStart) {
                moveOp.itemCount -= removeOp.itemCount;
            }
        } else {
            if (extraRm != null) {
                if (moveOp.positionStart >= extraRm.positionStart) {
                    moveOp.positionStart -= extraRm.itemCount;
                }
                if (moveOp.itemCount >= extraRm.positionStart) {
                    moveOp.itemCount -= extraRm.itemCount;
                }
            }
            if (moveOp.positionStart >= removeOp.positionStart) {
                moveOp.positionStart -= removeOp.itemCount;
            }
            if (moveOp.itemCount >= removeOp.positionStart) {
                moveOp.itemCount -= removeOp.itemCount;
            }
        }
        list.set(movePos, removeOp);
        if (moveOp.positionStart != moveOp.itemCount) {
            list.set(removePos, moveOp);
        } else {
            list.remove(removePos);
        }
        if (extraRm != null) {
            list.add(movePos, extraRm);
        }
    }

    private void swapMoveAdd(List<AdapterHelper.UpdateOp> list, int move, AdapterHelper.UpdateOp moveOp, int add, AdapterHelper.UpdateOp addOp) {
        int offset = 0;
        if (moveOp.itemCount < addOp.positionStart) {
            offset = 0 - 1;
        }
        if (moveOp.positionStart < addOp.positionStart) {
            offset++;
        }
        if (addOp.positionStart <= moveOp.positionStart) {
            moveOp.positionStart += addOp.itemCount;
        }
        if (addOp.positionStart <= moveOp.itemCount) {
            moveOp.itemCount += addOp.itemCount;
        }
        addOp.positionStart += offset;
        list.set(move, addOp);
        list.set(add, moveOp);
    }

    void swapMoveUpdate(List<AdapterHelper.UpdateOp> list, int move, AdapterHelper.UpdateOp moveOp, int update, AdapterHelper.UpdateOp updateOp) {
        AdapterHelper.UpdateOp extraUp1 = null;
        AdapterHelper.UpdateOp extraUp2 = null;
        if (moveOp.itemCount < updateOp.positionStart) {
            updateOp.positionStart--;
        } else if (moveOp.itemCount < updateOp.positionStart + updateOp.itemCount) {
            updateOp.itemCount--;
            extraUp1 = this.mCallback.obtainUpdateOp(4, moveOp.positionStart, 1, updateOp.payload);
        }
        if (moveOp.positionStart <= updateOp.positionStart) {
            updateOp.positionStart++;
        } else if (moveOp.positionStart < updateOp.positionStart + updateOp.itemCount) {
            int remaining = (updateOp.positionStart + updateOp.itemCount) - moveOp.positionStart;
            extraUp2 = this.mCallback.obtainUpdateOp(4, moveOp.positionStart + 1, remaining, updateOp.payload);
            updateOp.itemCount -= remaining;
        }
        list.set(update, moveOp);
        if (updateOp.itemCount > 0) {
            list.set(move, updateOp);
        } else {
            list.remove(move);
            this.mCallback.recycleUpdateOp(updateOp);
        }
        if (extraUp1 != null) {
            list.add(move, extraUp1);
        }
        if (extraUp2 != null) {
            list.add(move, extraUp2);
        }
    }

    private int getLastMoveOutOfOrder(List<AdapterHelper.UpdateOp> list) {
        boolean foundNonMove = false;
        for (int i = list.size() - 1; i >= 0; i--) {
            AdapterHelper.UpdateOp op1 = list.get(i);
            if (op1.cmd == 8) {
                if (foundNonMove) {
                    return i;
                }
            } else {
                foundNonMove = true;
            }
        }
        return -1;
    }
}
