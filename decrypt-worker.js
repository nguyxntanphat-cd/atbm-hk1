const { parentPort, workerData } = require('worker_threads');
const { createReceiver } = require('./receiver');
try {
  const receiver = createReceiver(workerData.keyDir); receiver.loadKeys();
  const plain = receiver.decryptPackage(workerData.pkg, workerData.passphrase, { allowLegacy: true });
  const bytes = Uint8Array.from(plain); plain.fill(0);
  parentPort.postMessage({ bytes }, [bytes.buffer]);
} catch (error) { parentPort.postMessage({ error: error.message, status: error.status || 422 }); }
