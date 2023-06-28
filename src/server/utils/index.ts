export async function retryConnection<T>(attempt: number, fn: Promise<T>, type: 'rabbitMQ', next: number) {
  let currentTry = 0;
  while (true) {
    try {
      const connection = await fn;
      console.log(`connect to ${type} succesfully`);
      return connection;
    } catch (error) {
      currentTry++;
      if (currentTry > attempt) {
        console.error(`connect to ${type} failed`);
        break;
      }
      console.log(`connect to ${type} failed at attemp: ${currentTry}`);
      await new Promise((resolve) => setTimeout(resolve, next * 1000));
    }
  }
}
