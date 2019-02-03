//
//  AppDelegate.swift
//  Ed25519-Swift-pod
//
//  Created by denn on 03/02/2019.
//  Copyright © 2019 Dehacer. All rights reserved.
//

import Cocoa
import ed25519

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet weak var window: NSWindow!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
       
        let pair = try! Pair(secretPhrase: "some secret phrase")
        let pair_random = Pair.random()

        let message = "some message or token string"
        var signature = pair.sign(message)

        Swift.print("Signature : \(signature.encode())")

        Swift.print("Signature verify: \(signature.verify(withPublic: pair.publicKey, string: message))")
        Swift.print("Signature verify random: \(signature.verify(withPublic: pair_random.publicKey, string: message))")

        var data = message.data(using: String.Encoding.utf8)!
        Swift.print("Signature verify data: \(signature.verify(withPublic: pair.publicKey, message: data))")

        let restored_signature = try! Signature(base58: signature.encode())
        Swift.print("Restored signature verify: \(restored_signature.verify(withPublic: pair.publicKey, message: data))")
        data.reverse()
        Swift.print("Restored signature verify modified data: \(restored_signature.verify(withPublic: pair.publicKey, message: data))")

        let digest = Digest { (calculator) in
            calculator
                .append(true)
                .append(3)
                .append("...")
                .append(pair.publicKey)
                .append(Seed())
            
        }
        Swift.print("Digest : \(digest.encode())")
        
        signature = pair.sign(digest)
        Swift.print("Signature : \(signature.encode())")
        Swift.print("Signature verify: \(signature.verify(withPublic: pair.publicKey, digest: digest))")
        Swift.print("Signature verify random: \(signature.verify(withPublic: pair_random.publicKey, digest: digest))")
        
        do {
            _ = try Signature(base58: "...some wrong base 58...")
        }
        catch {
            Swift.print("Error: \(error)")
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }


}

