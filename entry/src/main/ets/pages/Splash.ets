@Entry
@Component
struct Splash {
  private timeoutId: number = -1;

  aboutToAppear(): void {
    this.timeoutId = setTimeout(() => {
      this.getUIContext().getRouter().replaceUrl({ url: 'pages/Index' });
    }, 1000);
  }

  aboutToDisappear(): void {
    if (this.timeoutId >= 0) {
      clearTimeout(this.timeoutId);
      this.timeoutId = -1;
    }
  }

  build() {
    Stack() {
      Image($r('app.media.startup'))
        .width('100%')
        .height('100%')
        .objectFit(ImageFit.Contain)
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#FFFFFF')
  }
}
