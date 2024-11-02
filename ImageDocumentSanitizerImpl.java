package gov.afcat.utils;

import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

import org.apache.commons.imaging.ImageInfo;
import org.apache.commons.imaging.ImageParser;
import org.apache.commons.imaging.Imaging;
import org.apache.commons.imaging.formats.jpeg.JpegImageParser;
import org.apache.commons.imaging.formats.png.PngImageParser;
import org.apache.commons.io.FilenameUtils;
import org.springframework.util.ResourceUtils;

import gov.afcat.validators.imageValidation.CorruptJPEGDetector;



public class ImageDocumentSanitizerImpl  {
	
	private static final String ENC_ALGO = "AES";
	
	public boolean check(File file) throws Exception,NoSuchAlgorithmException , IOException {
		SecretKeySpec _secretKey = null;
	
		File filetoread=ResourceUtils.getFile("classpath:"+File.separator+"static"+File.separator+"biometric.txt");
		String key = null;
		String origKey = filetoread.toString();
		
		if(!filetoread.exists())
		{
			key = readFile(origKey);
			_secretKey = new SecretKeySpec(DatatypeConvertor.hexStringToByteArray(key), ENC_ALGO);
		}
		else
		{
			key = readFile(origKey);
			_secretKey = new SecretKeySpec(DatatypeConvertor.hexStringToByteArray(key), ENC_ALGO);
		}
		
	
		String fileExtension = FilenameUtils.getExtension(file.getAbsolutePath());
		if(fileExtension.equalsIgnoreCase("jpg") || fileExtension.equalsIgnoreCase("jpeg")) {
			 CorruptJPEGDetector obj = new CorruptJPEGDetector(Paths.get(file.getAbsolutePath()),false);
		
			if(obj.isJPEG() && obj.isFileComplete()) {		
				if(madeSafe(file)) {
					if(encryptDecryptImg(file , _secretKey)){
						return true;
					}
				}
				else {
					return false;
				}
			}  
		}else if(fileExtension.equalsIgnoreCase("png")) {
			 if(madeSafe(file)) {		 
				 if(encryptDecryptImg(file, _secretKey)) {
					return true;
				}
			}
			else { 
				return false; 
			}
		}else if(fileExtension.equalsIgnoreCase("pdf")) {			 
				 return true;
		}
		return false;
	}
	
	/** Read contents from a File **/
	
	String readFile(String fileName) throws IOException {
	    BufferedReader br = new BufferedReader(new FileReader(fileName));
	    try {
	        StringBuilder sb = new StringBuilder();
	        String line = br.readLine();

	        while (line != null) {
	            sb.append(line);
	            sb.append("\n");
	            line = br.readLine();
	        }
	        return sb.toString();
	    } finally {
	        br.close();
	    }
	}
	
	@SuppressWarnings("unused")
	public boolean encryptDecryptImg(File file,SecretKeySpec _secretKey) throws Exception {
        
        try{
       	 
       	 Path path = Paths.get(file.getAbsolutePath()); 
            byte[] data = Files.readAllBytes(path);
       	 
       	 Cipher cpr = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cpr.init(Cipher.ENCRYPT_MODE, _secretKey);
            
            byte[] textEncrypted = cpr.doFinal(data);
            
            cpr.init(Cipher.DECRYPT_MODE, _secretKey);
            byte[] textDecrypted = cpr.doFinal(textEncrypted);
            
            
            return true;
        }
        catch (Exception ex) {
            System.err.print(ex);
        }
        
        return false;
	 }
	
	public boolean decryptImg(String inFilePath, SecretKeySpec _secretKey) {
        try {
       	 Cipher cpr = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cpr.init(Cipher.DECRYPT_MODE, _secretKey);
            FileInputStream fileinput = new FileInputStream(inFilePath);
            CipherInputStream cis = new CipherInputStream(fileinput, cpr);
            BufferedImage input = ImageIO.read(cis);
            String fileExtension = FilenameUtils.getExtension(inFilePath);
            if(fileExtension.equalsIgnoreCase("jpg") || fileExtension.equalsIgnoreCase("jpeg")) {
                ImageIO.write(input, "jpg", new File(inFilePath));
            }
            else
            	ImageIO.write(input, "png", new File(inFilePath));
            return true;
        } catch (Exception ex) {
            System.err.print(ex);
        }
        
        return false;
	 }
	
	public boolean madeSafe(File f) {
		    boolean safeState = false;
	        boolean fallbackOnApacheCommonsImaging;
	        try {
	            if ((f != null) && f.exists() && f.canRead() && f.canWrite()) {
	                //Get the image format
	                String formatName;
	                try (ImageInputStream iis = ImageIO.createImageInputStream(f)) {
	                    Iterator<ImageReader> imageReaderIterator = ImageIO.getImageReaders(iis);
	                    //If there not ImageReader instance found so it's means that the current format is not supported by the Java built-in API
	                    if (!imageReaderIterator.hasNext()) {
	                        ImageInfo imageInfo = Imaging.getImageInfo(f);
	                        if (imageInfo != null && imageInfo.getFormat() != null && imageInfo.getFormat().getName() != null) {
	                            formatName = imageInfo.getFormat().getName();
	                            fallbackOnApacheCommonsImaging = true;
	                        } else {
	                            throw new IOException("Format of the original image is not supported for read operation !");
	                        }
	                    } else {
	                        ImageReader reader = imageReaderIterator.next();
	                        formatName = reader.getFormatName();
	                        fallbackOnApacheCommonsImaging = false;
	                    }
	                }

	                // Load the image
	                BufferedImage originalImage;
	                if (!fallbackOnApacheCommonsImaging) {
	                    originalImage = ImageIO.read(f);
	                } else {
	                    originalImage = Imaging.getBufferedImage(f);
	                }

	                // Check that image has been successfully loaded
	                if (originalImage == null) {
	                    throw new IOException("Cannot load the original image !");
	                }

	                // Get current Width and Height of the image
	                int originalWidth = originalImage.getWidth(null);
	                int originalHeight = originalImage.getHeight(null);


	                // Resize the image by removing 1px on Width and Height
	                Image resizedImage = originalImage.getScaledInstance(originalWidth - 1, originalHeight - 1, Image.SCALE_SMOOTH);

	                // Resize the resized image by adding 1px on Width and Height - In fact set image to is initial size
	                Image initialSizedImage = resizedImage.getScaledInstance(originalWidth, originalHeight, Image.SCALE_SMOOTH);

	                BufferedImage sanitizedImage = null;
	                String fileExtension = FilenameUtils.getExtension(f.getAbsolutePath());
	                if(fileExtension.equalsIgnoreCase("jpg") || fileExtension.equalsIgnoreCase("jpeg")) {
	                	sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), initialSizedImage.getHeight(null), BufferedImage.TYPE_INT_RGB);
	                }
	                else {
	                	BufferedImage imagebuffer = ImageIO.read(f);
	                	int iw = imagebuffer.getWidth();
	                	int ih = imagebuffer.getHeight();
	                	BufferedImage image = new BufferedImage(iw,ih,BufferedImage.TYPE_INT_ARGB);
	                	for (int x=0; x < iw; x++) {
	                	     for (int y=0; y < ih; y++) {
	                	          image.setRGB(x,y,imagebuffer.getRGB(x,y));
	                	     }
	                	}
	                	sanitizedImage=image;
		                //sanitizedImage = new BufferedImage(image.getWidth(null), image.getHeight(null), BufferedImage.TYPE_INT_RGB);
	                	
		                 //sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), initialSizedImage.getHeight(null), BufferedImage.TYPE_INT_ARGB);

	                }
	                // Save image by overwriting the provided source file content
	                
	                Graphics bg = sanitizedImage.getGraphics();
	                bg.drawImage(initialSizedImage, 0, 0, null);
	                bg.dispose();
	                try (OutputStream fos = Files.newOutputStream(f.toPath(), StandardOpenOption.WRITE)) {
	                    if (!fallbackOnApacheCommonsImaging) {
	                        ImageIO.write(sanitizedImage, formatName, fos); // this was increasing size of some images
	                    } else {
	                        ImageParser imageParser;
	                        //Handle only formats for which Apache Commons Imaging can successfully write (YES in Write column of the reference link) the image format
	                        //See reference link in the class header
	                        switch (formatName) {	                    	                                                    
	                            case "JPEG": {
	                                imageParser = new JpegImageParser();
	                                break;
	                            }
	                            case "PNG":
	                            {
	                            	imageParser=new PngImageParser();
	                            	break;
	                            }
	                            default: {
	                                throw new IOException("Format of the original image is not supported for write operation !");
	                            }

	                        }
	                        imageParser.writeImage(sanitizedImage, fos, new HashMap<>());
	                    }

	                }
	                // Set state flag
	                safeState = true;
	            }
	        } catch (Exception e) {
	            safeState = false;
	        }

	        return safeState;
	}

}
