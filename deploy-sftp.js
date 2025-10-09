// Script de despliegue SFTP
import Client from 'ssh2-sftp-client';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve, join } from 'path';
import fs from 'fs';

// Cargar variables de entorno
dotenv.config();

// Configurar rutas
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const localDir = resolve(__dirname, 'dist');
const remoteDir = process.env.VITE_SFTP_REMOTE_DIR || '/';
const keyPath = resolve(__dirname, 'keys/aws-kyber.pem');

// Función para unir rutas remotas usando siempre el separador de Linux
function joinRemotePath(...parts) {
  return parts.join('/').replace(/\/+/g, '/');
}

// Lista de archivos del directorio dist a desplegar
const distFiles = [
  {
    source: resolve(__dirname, 'dist/demo.html'),
    target: joinRemotePath(remoteDir, 'demo.html')
  },
  {
    source: resolve(__dirname, 'dist/index.html'),
    target: joinRemotePath(remoteDir, 'index.html')
  }
];

// Lista de archivos de la raíz a desplegar
const rootFiles = [
  {
    source: resolve(__dirname, '.htaccess'),
    target: joinRemotePath(remoteDir, '.htaccess')
  }
];

// Lista completa de archivos individuales a desplegar
const allFiles = [...distFiles, ...rootFiles];

// Directorios del directorio dist a desplegar
const distDirs = [
  {
    source: resolve(__dirname, 'dist/assets'),
    target: joinRemotePath(remoteDir, 'assets')
  }
];

// Directorios adicionales a desplegar
const additionalDirs = [
  {
    source: resolve(__dirname, 'api'),
    target: joinRemotePath(remoteDir, 'api')
  },
  {
    source: resolve(__dirname, 'api_client'),
    target: joinRemotePath(remoteDir, 'api_client')
  },
  {
    source: resolve(__dirname, 'api_server'),
    target: joinRemotePath(remoteDir, 'api_server')
  }
];

// Lista completa de directorios a desplegar
const allDirs = [...distDirs, ...additionalDirs];

// Función para crear directorios recursivamente
async function createRemoteDirectories(sftp, remotePath) {
  const dirs = remotePath.split('/').filter(dir => dir);
  let currentPath = '/';

  for (const dir of dirs) {
    currentPath = joinRemotePath(currentPath, dir);
    try {
      const stats = await sftp.stat(currentPath);
      if (!stats.isDirectory) {
        throw new Error(`Path ${currentPath} exists but is not a directory`);
      }
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Solo informar de la creación de directorios raíz, no subdirectorios
        if (dirs.length <= 2) {
          console.log(`Creando directorio: ${currentPath}`);
        }
        await sftp.mkdir(currentPath, true);
      } else {
        throw error;
      }
    }
  }
}

// Función para subir un directorio recursivamente
async function uploadDirectory(sftp, localPath, remotePath) {
  const files = fs.readdirSync(localPath);
  let filesProcessed = 0;
  const totalFiles = files.length;

  // Informar del total de archivos que se van a subir
  if (totalFiles > 0) {
    console.log(`Subiendo ${totalFiles} archivos del directorio ${localPath}`);
  }

  for (const file of files) {
    const localFilePath = join(localPath, file);
    const remoteFilePath = joinRemotePath(remotePath, file);
    const stats = fs.statSync(localFilePath);

    if (stats.isDirectory()) {
      await createRemoteDirectories(sftp, remoteFilePath);
      await uploadDirectory(sftp, localFilePath, remoteFilePath);
    } else {
      // Progreso silencioso, sólo mostrar de 10 en 10 para directorios grandes
      filesProcessed++;
      if (totalFiles > 20 && filesProcessed % 10 === 0) {
        console.log(`Progreso: ${filesProcessed}/${totalFiles} archivos en ${localPath}`);
      }

      try {
        await sftp.put(localFilePath, remoteFilePath);
      } catch (err) {
        console.error(`❌ Error al subir ${localFilePath} -> ${remoteFilePath}: ${err.message}`);
      }
    }
  }
}

// Verificar si la clave privada existe
function checkKeyFile() {
  if (!fs.existsSync(keyPath)) {
    console.error(`Error: No se encuentra el archivo de clave privada en ${keyPath}`);
    console.error('Por favor, asegúrate de que el archivo aws-kyber.pem está en el directorio keys/');
    return false;
  }

  // Ajustar permisos del archivo de clave en sistemas Unix-like
  try {
    if (process.platform !== 'win32') {
      fs.chmodSync(keyPath, 0o600);
      console.log('Permisos de la clave privada ajustados a 0600');
    }
  } catch (error) {
    console.warn('No se pudieron ajustar los permisos de la clave privada:', error.message);
    console.warn('Esto podría causar problemas si los permisos son demasiado abiertos');
  }

  return true;
}

// Obtener rutas válidas que se mantendrán en el servidor
function getValidPaths() {
  // Rutas de archivos válidos
  const validFiles = allFiles.map(file => file.target);

  // Rutas de directorios válidos
  const validDirs = allDirs.map(dir => dir.target);

  return {
    files: validFiles,
    dirs: validDirs
  };
}

// Función para obtener una lista plana de todos los archivos locales que se van a desplegar
async function getAllLocalFilePaths() {
  const fileList = [];

  // Añadir archivos individuales
  for (const file of allFiles) {
    if (fs.existsSync(file.source)) {
      fileList.push(file.target);
    }
  }

  // Añadir archivos de directorios de forma recursiva
  for (const dir of allDirs) {
    if (fs.existsSync(dir.source)) {
      await addFilesFromDirectory(dir.source, dir.target, fileList);
    }
  }

  return fileList;
}

// Función auxiliar para añadir archivos de un directorio de forma recursiva
async function addFilesFromDirectory(localPath, remotePath, fileList) {
  const files = fs.readdirSync(localPath);

  for (const file of files) {
    const localFilePath = join(localPath, file);
    const remoteFilePath = joinRemotePath(remotePath, file);
    const stats = fs.statSync(localFilePath);

    if (stats.isDirectory()) {
      await addFilesFromDirectory(localFilePath, remoteFilePath, fileList);
    } else {
      fileList.push(remoteFilePath);
    }
  }
}

// Función para limpiar archivos y directorios no deseados en el servidor
async function cleanObsoleteFiles(sftp) {
  console.log('Verificando y limpiando archivos obsoletos...');

  // Obtener lista de todos los archivos locales
  const localFiles = await getAllLocalFilePaths();

  // Función recursiva para verificar y limpiar directorios
  async function verifyAndCleanDirectory(remotePath) {
    // Ignorar el directorio logs y su contenido
    const logsPath = joinRemotePath(remoteDir, 'logs');
    if (remotePath === logsPath) {
      // No limpiar ni revisar nada dentro de logs
      return;
    }
    try {
      const listItems = await sftp.list(remotePath);

      for (const item of listItems) {
        const itemPath = joinRemotePath(remotePath, item.name);

        // Ignorar archivos y directorios especiales
        if (item.name === '.' || item.name === '..') continue;

        if (item.type === 'd') {
          // Es un directorio
          // Primero verificamos su contenido
          await verifyAndCleanDirectory(itemPath);

          // Después verificamos si el directorio está vacío
          try {
            const dirContents = await sftp.list(itemPath);
            // Filtrar . y ..
            const realContents = dirContents.filter(item => item.name !== '.' && item.name !== '..');

            if (realContents.length === 0) {
              // Si el directorio está vacío y no es uno de nuestros directorios principales, lo eliminamos
              const validPaths = getValidPaths();
              if (!validPaths.dirs.includes(itemPath)) {
                console.log(`Eliminando directorio vacío: ${itemPath}`);
                await sftp.rmdir(itemPath);
              }
            }
          } catch (err) {
            console.error(`Error al verificar si el directorio está vacío: ${itemPath}`, err.message);
          }
        } else {
          // Es un archivo, verificar si está en nuestra lista de archivos locales
          if (!localFiles.includes(itemPath)) {
            console.log(`Eliminando archivo obsoleto: ${itemPath}`);
            try {
              await sftp.delete(itemPath);
            } catch (err) {
              console.error(`Error al eliminar archivo ${itemPath}: ${err.message}`);
            }
          }
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error(`Error al verificar el directorio ${remotePath}:`, error.message);
      }
    }
  }

  // Verificar y limpiar el directorio raíz
  await verifyAndCleanDirectory(remoteDir);
  console.log('Limpieza completada');
}

// Función para eliminar un directorio remoto recursivamente
async function deleteRemoteDirectory(sftp, remotePath) {
  try {
    const listItems = await sftp.list(remotePath);

    // Primero eliminar todos los archivos y subdirectorios
    for (const item of listItems) {
      // Ignorar archivos y directorios especiales
      if (item.name === '.' || item.name === '..') continue;

      const itemPath = joinRemotePath(remotePath, item.name);

      if (item.type === 'd') {
        // Es un directorio, eliminarlo recursivamente
        await deleteRemoteDirectory(sftp, itemPath);
      } else {
        // Es un archivo, eliminarlo directamente
        try {
          await sftp.delete(itemPath);
        } catch (err) {
          console.error(`Error al eliminar archivo ${itemPath}: ${err.message}`);
        }
      }
    }

    // Ahora eliminar el directorio vacío
    await sftp.rmdir(remotePath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error(`Error al eliminar el directorio ${remotePath}:`, error.message);
      throw error;
    }
  }
}

// Subir archivos adicionales
async function uploadAdditionalFiles(sftp) {
  console.log('Subiendo archivos individuales...');
  let totalFiles = allFiles.length;
  let filesUploaded = 0;
  let filesWithErrors = 0;

  for (const file of allFiles) {
    if (fs.existsSync(file.source)) {
      // Informar del archivo que se va a subir
      console.log(`Subiendo: ${file.source} -> ${file.target}`);

      try {
        await sftp.put(file.source, file.target);
        filesUploaded++;

        // Si es un script shell, establecer permisos de ejecución
        if (file.source.endsWith('.sh')) {
          try {
            await sftp.chmod(file.target, 0o755);
          } catch (err) {
            console.warn(`⚠️ No se pudieron establecer permisos de ejecución para ${file.target}`, err.message);
          }
        }
      } catch (err) {
        console.error(`❌ Error al subir ${file.source}: ${err.message}`);
        filesWithErrors++;
      }
    } else {
      console.warn(`⚠️ El archivo ${file.source} no existe y será omitido`);
    }
  }

  //console.log(`Subida de archivos individuales: ${filesUploaded} exitosos, ${filesWithErrors} con errores de ${totalFiles} total`);
}

// Subir directorios adicionales
async function uploadAdditionalDirs(sftp) {
  //console.log('Subiendo directorios...');
  let dirsWithErrors = 0;
  let totalDirs = allDirs.length;

  for (const dir of allDirs) {
    if (fs.existsSync(dir.source)) {
      // Informar del directorio que se va a subir
      console.log(`Subiendo directorio: ${dir.source} -> ${dir.target}`);

      try {
        await createRemoteDirectories(sftp, dir.target);
        await uploadDirectory(sftp, dir.source, dir.target);
      } catch (err) {
        console.error(`❌ Error al subir directorio ${dir.source}: ${err.message}`);
        dirsWithErrors++;
      }
    } else {
      console.warn(`⚠️ El directorio ${dir.source} no existe y será omitido`);
    }
  }

  if (dirsWithErrors > 0) {
    console.warn(`⚠️ ${dirsWithErrors} de ${totalDirs} directorios tuvieron errores durante la subida`);
  } else {
    //console.log(`Subida de directorios completada: ${totalDirs} directorios procesados`);
  }
}

// Ejecutar el despliegue
async function deploy() {
  // Verificar si la clave privada existe
  if (!checkKeyFile()) {
    return;
  }

  // Verificar si estamos en Windows
  if (process.platform === 'win32') {
    console.error('❌ Este script debe ejecutarse en Linux/Unix, no en Windows (separadores de ruta incompatibles)');
    process.exit(1);
  }

  const sftp = new Client();

  try {
    console.log(`Conectando a ${process.env.VITE_SFTP_HOST} usando clave privada SSH...`);

    try {
      await sftp.connect({
        host: process.env.VITE_SFTP_HOST,
        port: parseInt(process.env.VITE_SFTP_PORT || '22'),
        username: process.env.VITE_SFTP_USER,
        privateKey: fs.readFileSync(keyPath),
        // Opcional: si tu clave tiene passphrase, descomenta la siguiente línea
      // passphrase: process.env.VITE_SFTP_KEY_PASSPHRASE,
      });
    } catch (err) {
      console.error('❌ Error al conectar al servidor SFTP:', err.message);
      process.exit(1);
    }

    //console.log('Conexión SFTP establecida con éxito');

    // Limpiar archivos y directorios obsoletos
    await cleanObsoleteFiles(sftp);

    // Crear el directorio remoto si no existe
    await createRemoteDirectories(sftp, remoteDir);

    // Crear el directorio logs si no existe
    await createRemoteDirectories(sftp, joinRemotePath(remoteDir, 'logs'));

    // Subir archivos individuales
    await uploadAdditionalFiles(sftp);

    // Subir directorios adicionales
    await uploadAdditionalDirs(sftp);

    console.log('Despliegue completado con éxito');
  } catch (err) {
    console.error('Error durante el despliegue:', err);
  } finally {
    sftp.end();
  }
}

// Iniciar despliegue
deploy();