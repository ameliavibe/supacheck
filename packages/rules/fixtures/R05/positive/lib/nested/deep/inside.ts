async function inner(url: string) {
  if (url) {
    return await fetch(url);
  }
}
