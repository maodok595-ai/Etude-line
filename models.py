from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Universite(Base):
    __tablename__ = "universites"
    
    id = Column(String, primary_key=True)
    nom = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False)
    logo_url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    ufrs = relationship("UFR", back_populates="universite", cascade="all, delete-orphan")
    etudiants = relationship("Etudiant", back_populates="universite")
    professeurs = relationship("Professeur", back_populates="universite")

class UFR(Base):
    __tablename__ = "ufrs"
    
    id = Column(String, primary_key=True)
    nom = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False)
    universite_id = Column(String, ForeignKey("universites.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    universite = relationship("Universite", back_populates="ufrs")
    filieres = relationship("Filiere", back_populates="ufr", cascade="all, delete-orphan")
    etudiants = relationship("Etudiant", back_populates="ufr")
    professeurs = relationship("Professeur", back_populates="ufr")

class Filiere(Base):
    __tablename__ = "filieres"
    
    id = Column(String, primary_key=True)
    nom = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False)
    ufr_id = Column(String, ForeignKey("ufrs.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    ufr = relationship("UFR", back_populates="filieres")
    matieres = relationship("Matiere", back_populates="filiere", cascade="all, delete-orphan")
    etudiants = relationship("Etudiant", back_populates="filiere")
    professeurs = relationship("Professeur", back_populates="filiere")
    chapitres = relationship("ChapitreComplet", back_populates="filiere")

class Matiere(Base):
    __tablename__ = "matieres"
    
    id = Column(String, primary_key=True)
    nom = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False)
    filiere_id = Column(String, ForeignKey("filieres.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    filiere = relationship("Filiere", back_populates="matieres")
    professeurs = relationship("Professeur", back_populates="matiere_obj")
    chapitres = relationship("ChapitreComplet", back_populates="matiere")
    contents = relationship("Content", back_populates="matiere")

class Administrateur(Base):
    __tablename__ = "administrateurs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    is_main_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Professeur(Base):
    __tablename__ = "professeurs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    specialite = Column(String(200), nullable=False)
    universite_id = Column(String, ForeignKey("universites.id"), nullable=True)
    ufr_id = Column(String, ForeignKey("ufrs.id"), nullable=True)
    filiere_id = Column(String, ForeignKey("filieres.id"), nullable=True)
    matiere_id = Column(String, ForeignKey("matieres.id"), nullable=True)
    # Rétrocompatibilité
    matiere = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    universite = relationship("Universite", back_populates="professeurs")
    ufr = relationship("UFR", back_populates="professeurs")
    filiere = relationship("Filiere", back_populates="professeurs")
    matiere_obj = relationship("Matiere", back_populates="professeurs")
    chapitres = relationship("ChapitreComplet", back_populates="professeur")
    contents = relationship("Content", back_populates="professeur")

class Etudiant(Base):
    __tablename__ = "etudiants"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    niveau = Column(String(10), nullable=False)
    universite_id = Column(String, ForeignKey("universites.id"), nullable=False)
    ufr_id = Column(String, ForeignKey("ufrs.id"), nullable=False)
    filiere_id = Column(String, ForeignKey("filieres.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    universite = relationship("Universite", back_populates="etudiants")
    ufr = relationship("UFR", back_populates="etudiants")
    filiere = relationship("Filiere", back_populates="etudiants")

class Content(Base):
    __tablename__ = "contents"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    niveau = Column(String(10), nullable=False)
    semestre = Column(String(10), nullable=False)
    chapitre = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False)  # cours, exercice, solution
    texte = Column(Text, nullable=True)
    fichier_nom = Column(String(500), nullable=True)
    fichier_path = Column(String(1000), nullable=True)
    matiere_id = Column(String, ForeignKey("matieres.id"), nullable=True)
    created_by = Column(String(100), ForeignKey("professeurs.username"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    matiere = relationship("Matiere", back_populates="contents")
    professeur = relationship("Professeur", back_populates="contents")

class ChapitreComplet(Base):
    __tablename__ = "chapitres_complets"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    universite_id = Column(String, ForeignKey("universites.id"), nullable=False)
    ufr_id = Column(String, ForeignKey("ufrs.id"), nullable=False)
    filiere_id = Column(String, ForeignKey("filieres.id"), nullable=False)
    matiere_id = Column(String, ForeignKey("matieres.id"), nullable=False)
    niveau = Column(String(10), nullable=False)
    semestre = Column(String(10), nullable=False)
    chapitre = Column(String(200), nullable=False)
    titre = Column(String(500), nullable=False)
    
    # Cours
    cours_texte = Column(Text, nullable=True)
    cours_fichier_nom = Column(String(500), nullable=True)
    cours_fichier_path = Column(String(1000), nullable=True)
    
    # Exercices
    exercice_texte = Column(Text, nullable=True)
    exercice_fichier_nom = Column(String(500), nullable=True)
    exercice_fichier_path = Column(String(1000), nullable=True)
    
    # Solutions
    solution_texte = Column(Text, nullable=True)
    solution_fichier_nom = Column(String(500), nullable=True)
    solution_fichier_path = Column(String(1000), nullable=True)
    
    created_by = Column(String(100), ForeignKey("professeurs.username"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    filiere = relationship("Filiere", back_populates="chapitres")
    matiere = relationship("Matiere", back_populates="chapitres")
    professeur = relationship("Professeur", back_populates="chapitres")