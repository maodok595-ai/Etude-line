from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float
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
    administrateurs = relationship("Administrateur", back_populates="universite")

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
    actif = Column(Boolean, default=True)
    universite_id = Column(String, ForeignKey("universites.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    universite = relationship("Universite", back_populates="administrateurs")

class Professeur(Base):
    __tablename__ = "professeurs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    specialite = Column(String(200), nullable=False)
    actif = Column(Boolean, default=True)
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
    quiz = relationship("Quiz", back_populates="professeur")

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
    tentatives_quiz = relationship("TentativeQuiz", back_populates="etudiant")
    remediations = relationship("Remediation", back_populates="etudiant")

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
    commentaires = relationship("Commentaire", back_populates="chapitre", cascade="all, delete-orphan")
    quiz = relationship("Quiz", back_populates="chapitre", cascade="all, delete-orphan")
    remediations = relationship("Remediation", back_populates="chapitre", cascade="all, delete-orphan")

class Commentaire(Base):
    __tablename__ = "commentaires"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    texte = Column(Text, nullable=False)
    chapitre_id = Column(Integer, ForeignKey("chapitres_complets.id"), nullable=False)
    auteur_type = Column(String(20), nullable=False)  # 'professeur' ou 'etudiant'
    auteur_id = Column(Integer, nullable=False)
    auteur_nom = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relations
    chapitre = relationship("ChapitreComplet", back_populates="commentaires")

class Quiz(Base):
    __tablename__ = "quiz"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    titre = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    chapitre_id = Column(Integer, ForeignKey("chapitres_complets.id"), nullable=False)
    duree_minutes = Column(Integer, nullable=True)  # Durée optionnelle du quiz
    note_passage = Column(Float, default=50.0)  # Note minimale pour réussir (%)
    created_by = Column(String(100), ForeignKey("professeurs.username"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    actif = Column(Boolean, default=True)
    
    # Relations
    chapitre = relationship("ChapitreComplet", back_populates="quiz")
    professeur = relationship("Professeur", back_populates="quiz")
    questions = relationship("Question", back_populates="quiz", cascade="all, delete-orphan")
    tentatives = relationship("TentativeQuiz", back_populates="quiz", cascade="all, delete-orphan")

class Question(Base):
    __tablename__ = "questions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    quiz_id = Column(Integer, ForeignKey("quiz.id"), nullable=False)
    texte = Column(Text, nullable=False)
    points = Column(Integer, default=1)  # Points accordés pour une bonne réponse
    ordre = Column(Integer, nullable=False)  # Ordre d'affichage de la question
    
    # Relations
    quiz = relationship("Quiz", back_populates="questions")
    reponses_options = relationship("ReponseOption", back_populates="question", cascade="all, delete-orphan")
    reponses_etudiants = relationship("ReponseEtudiant", back_populates="question", cascade="all, delete-orphan")

class ReponseOption(Base):
    __tablename__ = "reponses_options"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    question_id = Column(Integer, ForeignKey("questions.id"), nullable=False)
    texte = Column(String(500), nullable=False)
    est_correcte = Column(Boolean, default=False)
    
    # Relations
    question = relationship("Question", back_populates="reponses_options")

class TentativeQuiz(Base):
    __tablename__ = "tentatives_quiz"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    quiz_id = Column(Integer, ForeignKey("quiz.id"), nullable=False)
    etudiant_username = Column(String(100), ForeignKey("etudiants.username"), nullable=False)
    score = Column(Float, nullable=True)  # Score en pourcentage
    points_obtenus = Column(Integer, nullable=True)
    points_total = Column(Integer, nullable=True)
    reussi = Column(Boolean, default=False)
    date_debut = Column(DateTime, default=datetime.utcnow)
    date_fin = Column(DateTime, nullable=True)
    
    # Relations
    quiz = relationship("Quiz", back_populates="tentatives")
    etudiant = relationship("Etudiant", back_populates="tentatives_quiz")
    reponses = relationship("ReponseEtudiant", back_populates="tentative", cascade="all, delete-orphan")

class ReponseEtudiant(Base):
    __tablename__ = "reponses_etudiants"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tentative_id = Column(Integer, ForeignKey("tentatives_quiz.id"), nullable=False)
    question_id = Column(Integer, ForeignKey("questions.id"), nullable=False)
    reponse_option_id = Column(Integer, ForeignKey("reponses_options.id"), nullable=False)
    est_correcte = Column(Boolean, default=False)
    
    # Relations
    tentative = relationship("TentativeQuiz", back_populates="reponses")
    question = relationship("Question", back_populates="reponses_etudiants")

class Remediation(Base):
    __tablename__ = "remediations"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    etudiant_username = Column(String(100), ForeignKey("etudiants.username"), nullable=False)
    chapitre_id = Column(Integer, ForeignKey("chapitres_complets.id"), nullable=False)
    score_moyen = Column(Float, nullable=False)  # Score moyen de l'étudiant sur ce chapitre
    nb_tentatives = Column(Integer, default=0)
    suggestions = Column(Text, nullable=True)  # Suggestions personnalisées (JSON)
    date_creation = Column(DateTime, default=datetime.utcnow)
    date_mise_a_jour = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    etudiant = relationship("Etudiant", back_populates="remediations")
    chapitre = relationship("ChapitreComplet", back_populates="remediations")