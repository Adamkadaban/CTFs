package androidx.constraintlayout.core.widgets;
/* loaded from: classes.dex */
public class Rectangle {
    public int height;
    public int width;
    public int x;
    public int y;

    public void setBounds(int x, int y, int width, int height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    void grow(int w, int h) {
        this.x -= w;
        this.y -= h;
        this.width += w * 2;
        this.height += h * 2;
    }

    boolean intersects(Rectangle bounds) {
        int i;
        int i2;
        int i3 = this.x;
        int i4 = bounds.x;
        return i3 >= i4 && i3 < i4 + bounds.width && (i = this.y) >= (i2 = bounds.y) && i < i2 + bounds.height;
    }

    public boolean contains(int x, int y) {
        int i;
        int i2 = this.x;
        return x >= i2 && x < i2 + this.width && y >= (i = this.y) && y < i + this.height;
    }

    public int getCenterX() {
        return (this.x + this.width) / 2;
    }

    public int getCenterY() {
        return (this.y + this.height) / 2;
    }
}
